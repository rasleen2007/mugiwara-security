import type { Metadata } from "next";
import { getUserOrRedirect } from "@/lib/session";
import ScanClient from "./ScanClient";

export const metadata: Metadata = { title: "Scan" };

export default async function ScanPage({ params }: { params: { id: string } }) {
  await getUserOrRedirect();
  return <ScanClient jobId={params.id} />;
}
