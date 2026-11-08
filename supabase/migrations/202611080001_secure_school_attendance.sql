-- KNUST Smart School Management: security hardening + attendance RPCs
-- Review this migration before running it in the Supabase SQL Editor.
-- It preserves the five existing tables and their current column names.

create or replace function public.current_user_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid() limit 1;
$$;
revoke all on function public.current_user_role() from public;
grant execute on function public.current_user_role() to authenticated;

-- Ensure newly registered Auth users receive a student profile by default.
-- Privileged roles are assigned only by an administrator through the Edge Function.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, student_id, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    nullif(new.raw_user_meta_data->>'student_id', ''),
    'student'
  )
  on conflict (id) do update
    set full_name = excluded.full_name;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- Protect role and student ID from self-service changes.
create or replace function public.protect_profile_fields()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is not null
     and auth.uid() = old.id
     and public.current_user_role() <> 'admin'
     and (
       new.role is distinct from old.role
       or new.student_id is distinct from old.student_id
     )
  then
    raise exception 'You cannot change your role or student ID';
  end if;
  return new;
end;
$$;

drop trigger if exists protect_profile_fields on public.profiles;
create trigger protect_profile_fields
before update on public.profiles
for each row execute function public.protect_profile_fields();

-- Remove previous policies so there are no permissive-policy OR combinations
-- that accidentally grant broader access.
do $$
declare p record;
begin
  for p in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('profiles','courses','enrollments','class_sessions','attendance')
  loop
    execute format('drop policy if exists %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end $$;

alter table public.profiles enable row level security;
alter table public.courses enable row level security;
alter table public.enrollments enable row level security;
alter table public.class_sessions enable row level security;
alter table public.attendance enable row level security;

-- Profiles: users see themselves; lecturers see students enrolled in their courses;
-- all signed-in users may see lecturer names for the course directory; admins see all.
create policy profiles_select_self on public.profiles
for select to authenticated
using (
  id = auth.uid()
  or role = 'lecturer'
  or public.current_user_role() = 'admin'
  or (
    role = 'student'
    and exists (
      select 1 from public.enrollments e
      join public.courses c on c.id = e.course_id
      where e.student_id = profiles.id and c.lecturer_id = auth.uid()
    )
  )
);
create policy profiles_update_self on public.profiles
for update to authenticated
using (id = auth.uid() or public.current_user_role() = 'admin')
with check (id = auth.uid() or public.current_user_role() = 'admin');
create policy profiles_admin_insert on public.profiles
for insert to authenticated
with check (public.current_user_role() = 'admin');
create policy profiles_admin_delete on public.profiles
for delete to authenticated
using (public.current_user_role() = 'admin');

-- Courses: all authenticated users can browse; only admins manage globally;
-- lecturers may update their assigned course without transferring ownership.
create policy courses_select_authenticated on public.courses
for select to authenticated using (true);
create policy courses_admin_all on public.courses
for all to authenticated
using (public.current_user_role() = 'admin')
with check (public.current_user_role() = 'admin');
create policy courses_lecturer_update on public.courses
for update to authenticated
using (lecturer_id = auth.uid() and public.current_user_role() = 'lecturer')
with check (lecturer_id = auth.uid() and public.current_user_role() = 'lecturer');

-- Enrolments: admin manages; students see only their own; lecturers see enrolments
-- for courses assigned to them.
create policy enrollments_select_relevant on public.enrollments
for select to authenticated
using (
  student_id = auth.uid()
  or public.current_user_role() = 'admin'
  or exists (
    select 1 from public.courses c
    where c.id = enrollments.course_id and c.lecturer_id = auth.uid()
  )
);
create policy enrollments_admin_all on public.enrollments
for all to authenticated
using (public.current_user_role() = 'admin')
with check (public.current_user_role() = 'admin');

-- Sessions: readable only by admin, owning lecturer, or enrolled students.
-- Creation is through start_class_session RPC, not direct browser inserts.
create policy sessions_select_relevant on public.class_sessions
for select to authenticated
using (
  public.current_user_role() = 'admin'
  or lecturer_id = auth.uid()
  or exists (
    select 1 from public.enrollments e
    where e.course_id = class_sessions.course_id and e.student_id = auth.uid()
  )
);
create policy sessions_admin_delete on public.class_sessions
for delete to authenticated using (public.current_user_role() = 'admin');
create policy sessions_lecturer_delete on public.class_sessions
for delete to authenticated
using (lecturer_id = auth.uid() and public.current_user_role() = 'lecturer');

-- Attendance: student sees own; lecturer sees attendance for their own sessions;
-- admin sees all. Inserts are only through mark_class_attendance RPC.
create policy attendance_select_relevant on public.attendance
for select to authenticated
using (
  student_id = auth.uid()
  or public.current_user_role() = 'admin'
  or exists (
    select 1 from public.class_sessions s
    where s.id = attendance.session_id and s.lecturer_id = auth.uid()
  )
);
create policy attendance_admin_delete on public.attendance
for delete to authenticated using (public.current_user_role() = 'admin');

-- Server-side class-session creation. Lecturer must own the selected course.
create or replace function public.start_class_session(
  p_course_id uuid,
  p_duration_minutes integer,
  p_latitude double precision,
  p_longitude double precision
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role text;
  v_session_id uuid;
begin
  v_role := public.current_user_role();
  if auth.uid() is null or v_role not in ('admin','lecturer') then
    raise exception 'Only administrators and lecturers can start classes';
  end if;
  if p_duration_minutes is null or p_duration_minutes < 1 or p_duration_minutes > 90 then
    raise exception 'Duration must be between 1 and 90 minutes';
  end if;
  if p_latitude is null or p_longitude is null
     or p_latitude not between -90 and 90
     or p_longitude not between -180 and 180 then
    raise exception 'Valid location coordinates are required';
  end if;
  if not exists (
    select 1 from public.courses c
    where c.id = p_course_id
      and (v_role = 'admin' or c.lecturer_id = auth.uid())
  ) then
    raise exception 'You are not assigned to this course';
  end if;

  insert into public.class_sessions
    (course_id, lecturer_id, attendance_code, starts_at, ends_at, latitude, longitude, radius_m)
  values
    (p_course_id, auth.uid(), replace(gen_random_uuid()::text, '-', ''),
     now(), now() + make_interval(mins => p_duration_minutes),
     p_latitude, p_longitude, 150)
  returning id into v_session_id;
  return v_session_id;
end;
$$;
revoke all on function public.start_class_session(uuid,integer,double precision,double precision) from public;
grant execute on function public.start_class_session(uuid,integer,double precision,double precision) to authenticated;

-- Server-side attendance validation: active code, enrolled student, one check-in,
-- and distance from lecturer's saved class location are checked in the database.
create or replace function public.mark_class_attendance(
  p_attendance_code text,
  p_latitude double precision,
  p_longitude double precision,
  p_accuracy_m integer default 0
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_session public.class_sessions%rowtype;
  v_distance double precision;
  v_id uuid;
  v_accuracy integer;
  v_lat1 double precision;
  v_lat2 double precision;
  v_dlat double precision;
  v_dlon double precision;
  v_a double precision;
begin
  if auth.uid() is null or public.current_user_role() <> 'student' then
    raise exception 'Only student accounts can submit attendance';
  end if;
  if p_attendance_code is null or length(trim(p_attendance_code)) < 12 then
    raise exception 'Enter a valid attendance code';
  end if;
  if p_latitude is null or p_longitude is null
     or p_latitude not between -90 and 90
     or p_longitude not between -180 and 180 then
    raise exception 'Valid location coordinates are required';
  end if;

  select * into v_session
  from public.class_sessions
  where attendance_code = trim(p_attendance_code)
  limit 1;

  if not found then raise exception 'Attendance code is not valid'; end if;
  if v_session.ends_at is null or now() > v_session.ends_at then
    raise exception 'This attendance code has expired';
  end if;
  if now() < v_session.starts_at then raise exception 'This class has not started'; end if;
  if not exists (
    select 1 from public.enrollments e
    where e.course_id = v_session.course_id and e.student_id = auth.uid()
  ) then
    raise exception 'You are not enrolled in this course';
  end if;
  if v_session.latitude is null or v_session.longitude is null then
    raise exception 'Class location is not configured';
  end if;

  v_accuracy := greatest(0, least(coalesce(p_accuracy_m,0),50));
  v_lat1 := radians(v_session.latitude);
  v_lat2 := radians(p_latitude);
  v_dlat := radians(p_latitude - v_session.latitude);
  v_dlon := radians(p_longitude - v_session.longitude);
  v_a := sin(v_dlat/2)^2 + cos(v_lat1)*cos(v_lat2)*sin(v_dlon/2)^2;
  v_distance := 6371000 * 2 * atan2(sqrt(v_a), sqrt(greatest(0,1-v_a)));

  if v_distance > coalesce(v_session.radius_m,150) + v_accuracy then
    raise exception 'You are outside the permitted class location radius (distance: % metres)', round(v_distance)::integer;
  end if;

  insert into public.attendance
    (session_id, student_id, latitude, longitude, distance_m, marked_at)
  values
    (v_session.id, auth.uid(), p_latitude, p_longitude, v_distance, now())
  returning id into v_id;
  return v_id;
exception
  when unique_violation then
    raise exception 'Attendance has already been recorded for this class';
end;
$$;
revoke all on function public.mark_class_attendance(text,double precision,double precision,integer) from public;
grant execute on function public.mark_class_attendance(text,double precision,double precision,integer) to authenticated;
