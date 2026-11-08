KNUST SMART SCHOOL MANAGEMENT & CLASS ATTENDANCE — DEMO

DEMO LOGINS
Admin: admin@knust.edu.gh / Admin123
Lecturer: lecturer@knust.edu.gh / Teach123
Student: 70012345 / Student123

LIVE LOCATION FEATURE
- When a lecturer starts a class, the browser requests permission to capture the lecturer's location.
- When a student submits an attendance code, the browser requests permission to capture the student's location.
- The demo compares the two locations and accepts attendance within an approximate 150-metre range, with tolerance for GPS accuracy.
- Location is requested only during these actions, not continuously in the background.
- Users must be informed why location is requested and must grant permission.
- Geolocation generally requires HTTPS or localhost. Deploy to an HTTPS host such as Netlify to test it.

IMPORTANT LIMITATIONS
This is a front-end demonstration, not a production-ready university system.
- Data is stored in localStorage on the current browser only. Different devices do NOT share data yet.
- Client-side location checks can be spoofed and are not secure proof of physical presence.
- Do not use real student records, passwords or location data in this demo.
- Before real deployment, connect a secure shared database and server-side authentication/authorization (for example Supabase), validate attendance and location on the server, and provide clear privacy notices and consent.
- Browser location is a one-time coordinate reading, not continuous live tracking.

Extract the ZIP and open index.html. Deploy to HTTPS to test location access.
