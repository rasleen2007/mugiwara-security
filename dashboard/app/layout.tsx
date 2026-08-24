/**
 * Root layout — wraps every page.
 * Server Component: reads user session for NavBar, sets HTML metadata.
 */

import type { Metadata } from "next";
import "./globals.css";
import NavBar from "@/components/NavBar";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: {
    default: "Mugiwara Security",
    template: "%s — Mugiwara Security",
  },
  description:
    "Autonomous AI-powered security testing and vulnerability verification platform.",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const supabase = createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  return (
    <html lang="en">
      <body>
        <NavBar userEmail={user?.email ?? null} />
        <main className="main-content">{children}</main>
      </body>
    </html>
  );
}
