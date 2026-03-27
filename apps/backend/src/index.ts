import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import { cookie } from "@elysiajs/cookie";
import { prisma } from "../prisma/db";
import { createOAuthClient, getAuthUrl } from "./auth";
import { getCourses, getCourseWorks, getSubmissions } from "./classroom";
import type { ApiResponse, HealthCheck, User } from "shared";
import path from "path";
import fs from "fs";

// --- HELPERS ---

// Fungsi untuk mendeteksi akses langsung dari browser (bukan via AJAX/Fetch)
const isBrowserRequest = (request: Request): boolean => {
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  const accept = request.headers.get("accept") ?? "";

  const acceptsHtml = accept.includes("text/html");

  // Jika menerima HTML tapi tidak punya origin/referer = akses langsung URL
  return acceptsHtml && !origin && !referer;
};

// In-memory token store
const tokenStore = new Map<string, { access_token: string; refresh_token?: string }>();

const app = new Elysia()
  // Menggunakan URL dari ENV untuk CORS. TEST_URL bisa diisi "*" untuk dev.
  .use(cors({ 
    origin: [process.env.FRONTEND_URL ?? "", process.env.TEST_URL ?? ""], 
    credentials: true 
  }))
  .use(swagger())
  .use(cookie())
  
  // LOGIK KEAMANAN: Proteksi /users dengan API_KEY
  .onRequest(({ request, set }) => {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/users")) {
      const origin = request.headers.get("origin");
      const frontendUrl = process.env.FRONTEND_URL ?? "";

      // Jika request dari FRONTEND_URL resmi → izinkan
      if (origin && origin === frontendUrl) return;

      // Jika akses browser langsung atau dari tempat lain → wajib cek key
      if (isBrowserRequest(request) || (origin && origin !== frontendUrl)) {
        const key = url.searchParams.get("key");

        if (!key || key !== process.env.API_KEY) {
          set.status = 401;
          return { message: "Unauthorized: missing or invalid key" };
        }
      }
    }
  })

  // Health check
  .get("/", (): ApiResponse<HealthCheck> => ({
    data: { status: "ok" },
    message: "server running",
  }))

  // Endpoint Debug Prisma (Untuk cek apakah client ter-generate di Vercel)
  .get("/debug-prisma", () => {
    const generatedPath = path.resolve(__dirname, "../src/generated/prisma/client");
    const exists = fs.existsSync(generatedPath);

    return {
      path: generatedPath,
      exists: exists,
      files: exists ? fs.readdirSync(generatedPath) : []
    };
  })

  // Users (Terproteksi oleh onRequest di atas)
  .get("/users", async () => {
    const users = await prisma.user.findMany();
    return {
      data: users,
      message: "User list retrieved",
    } as ApiResponse<User[]>;
  })

  // --- AUTH ROUTES ---

  .get("/auth/login", ({ redirect }) => {
    const oauth2Client = createOAuthClient();
    const url = getAuthUrl(oauth2Client);
    return redirect(url);
  })

  .get("/auth/callback", async ({ query, set, cookie: { session }, redirect }) => {
    const { code } = query as { code: string };

    if (!code) {
      set.status = 400;
      return { error: "Missing authorization code" };
    }

    const oauth2Client = createOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);

    const sessionId = crypto.randomUUID();
    tokenStore.set(sessionId, {
      access_token: tokens.access_token!,
      refresh_token: tokens.refresh_token ?? undefined,
    });

    if (session) {
      session.value = sessionId;
      session.maxAge = 60 * 60 * 24; 
      session.path = "/"; // Pastikan cookie bisa dibaca di semua path
    }

    // Redirect DYNAMIC menggunakan FRONTEND_URL dari ENV
    return redirect(`${process.env.FRONTEND_URL}/classroom`);
  })

  .get("/auth/me", ({ cookie: { session } }) => {
    const sessionId = session?.value as string;
    if (!sessionId || !tokenStore.has(sessionId)) {
      return { loggedIn: false };
    }
    return { loggedIn: true, sessionId };
  })

  .post("/auth/logout", ({ cookie: { session } }) => {
    if (!session) return { success: false };
    const sessionId = session.value as string;
    if (sessionId) {
      tokenStore.delete(sessionId);
      session.remove();
    }
    return { success: true };
  })

  // --- CLASSROOM ROUTES ---

  .get("/classroom/courses", async ({ cookie: { session }, set }) => {
    const sessionId = session?.value as string;
    const tokens = sessionId ? tokenStore.get(sessionId) : null;

    if (!tokens) {
      set.status = 401;
      return { error: "Unauthorized. Silakan login terlebih dahulu." };
    }

    const courses = await getCourses(tokens.access_token);
    return { data: courses, message: "Courses retrieved" };
  })

  .get("/classroom/courses/:courseId/submissions", async ({ params, cookie: { session }, set }) => {
    const sessionId = session?.value as string;
    const tokens = sessionId ? tokenStore.get(sessionId) : null;

    if (!tokens) {
      set.status = 401;
      return { error: "Unauthorized. Silakan login terlebih dahulu." };
    }

    const { courseId } = params;
    const [courseWorks, submissions] = await Promise.all([
      getCourseWorks(tokens.access_token, courseId),
      getSubmissions(tokens.access_token, courseId),
    ]);

    const submissionMap = new Map(submissions.map((s) => [s.courseWorkId, s]));
    const result = courseWorks.map((cw) => ({
      courseWork: cw,
      submission: submissionMap.get(cw.id) ?? null,
    }));

    return { data: result, message: "Course submissions retrieved" };
  });

// --- SERVER LISTEN & LOGS ---

// Hanya jalankan app.listen() dan logs jika BUKAN di production (Vercel handle listen otomatis)
if (process.env.NODE_ENV !== "production") {
  app.listen(3000);
  console.log(`🦊 Backend Running on http://localhost:3000`);
  console.log(`🦊 FRONTEND_URL: ${process.env.FRONTEND_URL}`);
  console.log(`🦊 TEST_URL: ${process.env.TEST_URL}`);
  console.log(`🦊 DATABASE_URL: ${process.env.DATABASE_URL ? "Connected ✅" : "Missing ❌"}`);
}

// Export default wajib agar Vercel dapat membaca instance Elysia sebagai handler
export type App = typeof app;
export default app;