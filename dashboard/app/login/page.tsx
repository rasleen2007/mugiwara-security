import type { Metadata } from "next";
import LoginForm from "./LoginForm";

export const metadata: Metadata = { title: "Log in" };

export default function LoginPage() {
  return (
    <div className="auth-container">
      <div className="card">
        <div className="auth-title">
          <h1>Log in</h1>
          <p className="text-sm mt-2">
            Sign in to your Mugiwara Security account to run scans and review
            reports.
          </p>
        </div>
        <LoginForm />
      </div>
    </div>
  );
}
