"use client";

/**
 * Logout control — Client Component.
 *
 * Calls supabase.auth.signOut() which clears the HttpOnly session cookies
 * (via @supabase/ssr cookie integration), then hard-navigates to /login.
 * No tokens are ever touched directly.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";
import { createClient } from "@/lib/supabase/client";

export default function LogoutButton() {
  const router = useRouter();
  const [signingOut, setSigningOut] = useState(false);

  async function handleLogout() {
    setSigningOut(true);
    try {
      const supabase = createClient();
      await supabase.auth.signOut();
      // Full navigation so all server components re-render unauthenticated.
      window.location.assign("/login");
    } catch {
      // Even if sign-out fails, force the user out of protected pages.
      window.location.assign("/login");
    }
  }

  return (
    <button
      type="button"
      className="btn btn-secondary btn-sm"
      onClick={handleLogout}
      disabled={signingOut}
    >
      {signingOut ? "Signing out…" : "Log out"}
    </button>
  );
}
