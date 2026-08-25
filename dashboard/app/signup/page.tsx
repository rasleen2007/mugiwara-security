import type { Metadata } from "next";
import SignupForm from "./SignupForm";

export const metadata: Metadata = { title: "Sign up" };

export default function SignupPage() {
  return (
    <div className="auth-container">
      <div className="card">
        <div className="auth-title">
          <h1>Create your account</h1>
          <p className="text-sm mt-2">
            Sign up to run security scans on your source code and review the
            resulting reports.
          </p>
        </div>
        <SignupForm />
      </div>
    </div>
  );
}
