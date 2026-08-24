/**
 * Server-side session helpers.
 *
 * requireUser() returns the authenticated Supabase user or redirects to
 * /login. Every protected Server Component calls this before rendering.
 * Middleware already blocks unauthenticated traffic — this is defence in
 * depth (middleware cookies can't be trusted on their own).
 */

import { redirect } from "next/navigation";
import type { User } from "@supabase/supabase-js";
import { createClient } from "@/lib/supabase/server";

export async function getUserOrRedirect(): Promise<User> {
  const supabase = createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    redirect("/login");
  }
  return user;
}
