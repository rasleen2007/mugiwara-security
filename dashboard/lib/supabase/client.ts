/**
 * Supabase browser client (Next.js App Router).
 *
 * Uses @supabase/ssr createBrowserClient which persists the session in
 * cookies (not localStorage), so the session is visible to server-side
 * code and middleware without any custom cookie handling.
 *
 * This file must only be imported in Client Components ("use client").
 */

"use client";

import { createBrowserClient } from "@supabase/ssr";

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}
