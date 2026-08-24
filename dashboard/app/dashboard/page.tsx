import type { Metadata } from "next";
import { getUserOrRedirect } from "@/lib/session";
import DashboardClient from "./DashboardClient";

export const metadata: Metadata = { title: "Dashboard" };

export default async function DashboardPage() {
  await getUserOrRedirect();
  return <DashboardClient />;
}
