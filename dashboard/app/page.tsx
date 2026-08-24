import { redirect } from "next/navigation";
import { getUserOrRedirect } from "@/lib/session";

/** Root route — authenticated users land on /dashboard, others on /login. */
export default async function HomePage() {
  // Redirects to /login when there is no valid session.
  await getUserOrRedirect();
  redirect("/dashboard");
}
