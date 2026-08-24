/**
 * Supabase server-side client (Next.js App Router).
 *
 * Uses @supabase/ssr which stores the session in HttpOnly cookies managed
 * by Next.js middleware — not in localStorage or custom cookies.
 *
 * This file must only be imported in:
 *   - Server Components
 *   - Route Handlers
 *   - Server Actions
 *
 * It must NEVER be imported in Client Components (use lib/supabase/client.ts).
 */

import { createServerClient } from "@supabase/ssr";
import type { CookieOptions } from "@supabase/ssr";
import { cookies } from "next/headers";

interface CookieToSet {
  name: string;
  value: string;
  options: CookieOptions;
}

export function createClient() {
  const cookieStore = cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet: CookieToSet[]) {
          try {
            cookiesToSet.forEach(({ name, value, options }) => {
              cookieStore.set(name, value, options);
            });
          } catch {
            // The `setAll` method is called from a Server Component.
            // This can be ignored if you have middleware refreshing
            // user sessions.
          }
        },
      },
    }
  );
}
