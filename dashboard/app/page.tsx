import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import LandingPage from "./LandingPage";

/**
 * Root route — always shows the public landing page to unauthenticated
 * visitors.  Authenticated users are silently redirected to /dashboard.
 *
 * The auth check is wrapped in a try/catch so that a Supabase outage or
 * misconfiguration can never prevent the public landing page from loading.
 */
export default async function HomePage() {
  try {
    const supabase = createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (user) {
      redirect("/dashboard");
    }
  } catch {
    // If auth check fails, fall through and render the public landing page.
  }

  return <LandingPage />;
}
