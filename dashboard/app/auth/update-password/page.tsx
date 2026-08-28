import type { Metadata } from "next";
import { getUserOrRedirect } from "@/lib/session";
import UpdatePasswordForm from "./UpdatePasswordForm";

export const metadata: Metadata = { title: "Set a new password" };

export default async function UpdatePasswordPage() {
  // A valid session (created by exchanging the recovery code in
  // /auth/callback) is required to set a new password. Without one the user
  // is redirected to /login.
  await getUserOrRedirect();

  return (
    <div className="auth-container">
      <div className="card">
        <div className="auth-title">
          <h1>Set a new password</h1>
          <p className="text-sm mt-2">
            Choose a new password for your Mugiwara Security account.
          </p>
        </div>
        <UpdatePasswordForm />
      </div>
    </div>
  );
}
