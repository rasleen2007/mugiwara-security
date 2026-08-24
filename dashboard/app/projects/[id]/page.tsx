import type { Metadata } from "next";
import { getUserOrRedirect } from "@/lib/session";
import ProjectDetailClient from "./ProjectDetailClient";

export const metadata: Metadata = { title: "Project" };

export default async function ProjectPage({
  params,
}: {
  params: { id: string };
}) {
  await getUserOrRedirect();
  return <ProjectDetailClient projectId={params.id} />;
}
