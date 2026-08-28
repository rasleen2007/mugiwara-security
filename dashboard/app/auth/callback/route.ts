import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

/**
 * Auth callback — exchanges a Supabase authorization code for a session.
 *
 * Handles two flows:
 * - Email confirmation / magic link: the code yields a normal session, and the
 *   user lands on `next` (default /dashboard).
 * - Password recovery: the code yields a recovery session, and the user is sent
 *   to /auth/update-password to set a new password.
 *
 * `next` is only honored when it is a safe, same-site relative path.
 */
export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const type = searchParams.get("type");
  const rawNext = searchParams.get("next");
  const next =
    rawNext && rawNext.startsWith("/") && !rawNext.startsWith("//")
      ? rawNext
      : null;

  if (code) {
    const supabase = createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      // A recovery code (from the "forgot password" flow) must take the user
      // to the screen where they set a new password.
      if (type === "recovery" || next === "/auth/update-password") {
        return NextResponse.redirect(`${origin}/auth/update-password`);
      }
      return NextResponse.redirect(`${origin}${next ?? "/dashboard"}`);
    }
  }

  return NextResponse.redirect(`${origin}/login?error=auth_callback_error`);
}
