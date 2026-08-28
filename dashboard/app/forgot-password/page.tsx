import type { Metadata } from "next";
import ForgotPasswordForm from "./ForgotPasswordForm";

export const metadata: Metadata = { title: "Forgot password" };

export default function ForgotPasswordPage() {
  return (
    <div className="auth-container">
      <div className="card">
        <div className="auth-title">
          <h1>Reset your password</h1>
          <p className="text-sm mt-2">
            Enter the email address for your Mugiwara Security account and
            we&apos;ll send you a link to set a new password.
          </p>
        </div>
        <ForgotPasswordForm />
      </div>
    </div>
  );
}
