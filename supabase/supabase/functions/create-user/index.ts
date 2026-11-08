
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const respond = (body: object, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) return respond({ error: "Not authorized" }, 401);

    const callerClient = createClient(url, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: { user }, error: userError } =
      await callerClient.auth.getUser();

    if (userError || !user) {
      return respond({ error: "Invalid login" }, 401);
    }

    const adminClient = createClient(url, serviceKey);

    const { data: profile, error: profileError } = await adminClient
      .from("profiles")
      .select("role")
      .eq("id", user.id)
      .single();

    if (profileError || profile?.role !== "admin") {
      return respond({ error: "Administrator access required" }, 403);
    }

    const { email, password, full_name, student_id, role } =
      await req.json();

    if (!email || !password || !full_name || !role) {
      return respond({ error: "Missing required fields" }, 400);
    }

    if (!["student", "lecturer", "admin"].includes(role)) {
      return respond({ error: "Invalid role" }, 400);
    }

    if (password.length < 8) {
      return respond({ error: "Password must be at least 8 characters" }, 400);
    }

    const { data: created, error: createError } =
      await adminClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name, student_id, role },
      });

    if (createError || !created.user) {
      return respond({ error: createError?.message || "User creation failed" }, 400);
    }

    const { error: saveError } = await adminClient
      .from("profiles")
      .upsert({
        id: created.user.id,
        full_name,
        student_id: student_id || null,
        role,
      });

    if (saveError) {
      await adminClient.auth.admin.deleteUser(created.user.id);
      return respond({ error: saveError.message }, 400);
    }

    return respond({
      message: "Account created successfully",
      user_id: created.user.id,
    });
  } catch (error) {
    return respond({
      error: error instanceof Error ? error.message : "Unexpected error",
    }, 500);
  }
});
