import type { Metadata } from "next";
import { getUserOrRedirect } from "@/lib/session";
import ReportClient from "./ReportClient";

export const metadata: Metadata = { title: "Report" };

export default async function ReportPage({ params }: { params: { id: string } }) {
  await getUserOrRedirect();
  return <ReportClient reportId={params.id} />;
}
