/**
 * Next.js middleware — Supabase session refresh and route protection.
 *
 * Responsibilities:
 * 1. Refresh the Supabase auth session on every request so that HttpOnly
 *    session cookies are kept up-to-date. (@supabase/ssr requirement.)
 * 2. Redirect unauthenticated users away from protected routes to /login.
 * 3. Redirect authenticated users away from /login to /dashboard.
 *
 * Security notes:
 * - Uses supabase.auth.getUser() (not getSession()) for the auth check,
 *   because getUser() re-validates the token against the auth server.
 * - This is defence-in-depth: server components also check auth before
 *   rendering any protected content.
 * - The middleware never logs tokens, Authorization headers, or session data.
 */

import { createServerClient } from "@supabase/ssr";
import type { CookieOptions } from "@supabase/ssr";
import { type NextRequest, NextResponse } from "next/server";

interface CookieToSet {
  name: string;
  value: string;
  options: CookieOptions;
}

/** Routes that require an authenticated session. */
const PROTECTED_PREFIXES = [
  "/dashboard",
  "/projects",
  "/scans",
  "/reports",
];

function isProtected(pathname: string): boolean {
  return PROTECTED_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

export async function middleware(request: NextRequest) {
  let supabaseResponse = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet: CookieToSet[]) {
          // Forward cookie mutations to both the outgoing request and the
          // response so the server client can read them on the next request.
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          supabaseResponse = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // IMPORTANT: getUser() re-validates the token server-side.
  // Do not use getSession() here — it only reads local cookies and can be
  // spoofed by a tampered cookie.
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { pathname } = request.nextUrl;

  // Unauthenticated access to a protected route → redirect to login.
  if (!user && isProtected(pathname)) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    // Preserve the intended destination so login can redirect back.
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Authenticated user trying to visit /login → redirect to dashboard.
  if (user && pathname === "/login") {
    const dashboardUrl = request.nextUrl.clone();
    dashboardUrl.pathname = "/dashboard";
    dashboardUrl.search = "";
    return NextResponse.redirect(dashboardUrl);
  }

  // Return the (possibly cookie-mutated) response.
  return supabaseResponse;
}

export const config = {
  matcher: [
    /*
     * Match all paths except:
     * - _next/static (static files)
     * - _next/image  (image optimisation)
     * - favicon.ico, robots.txt, sitemap.xml
     * This ensures the session is refreshed on every navigation.
     */
    "/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)",
  ],
};
