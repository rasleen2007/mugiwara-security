import type { Metadata } from "next";
import DemoClient from "./DemoClient";

export const metadata: Metadata = {
  title: "Demo",
  description:
    "Explore a sample Mugiwara Security report — no account required.",
};

/**
 * Public /demo route — guest demo mode.
 *
 * Deliberately NOT wrapped in any auth guard and NOT in middleware's
 * PROTECTED_PREFIXES, so unauthenticated visitors can explore a sample
 * report. Every data point is static sample content from lib/demo-data.ts;
 * the page never calls authenticated API endpoints.
 */
export default function DemoPage() {
  return <DemoClient />;
}
