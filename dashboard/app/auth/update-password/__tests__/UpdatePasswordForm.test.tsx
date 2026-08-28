/**
 * Update-password (recovery) form tests.
 *
 * Covers: rendering + validation, calling auth.updateUser({ password }) to set
 * the new password securely, success messaging, and safe error mapping (never
 * echo provider internals).
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import UpdatePasswordForm from "@/app/auth/update-password/UpdatePasswordForm";

const updateUserMock = vi.fn();

vi.mock("@/lib/supabase/client", () => ({
  createClient: () => ({
    auth: {
      updateUser: updateUserMock,
    },
  }),
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

beforeEach(() => {
  updateUserMock.mockReset();
});

async function fillAndSubmit(
  overrides: Partial<{
    "New password": string;
    "Confirm new password": string;
  }> = {}
) {
  const user = userEvent.setup();
  await user.type(
    screen.getByLabelText("New password"),
    overrides["New password"] ?? "secret123"
  );
  await user.type(
    screen.getByLabelText("Confirm new password"),
    overrides["Confirm new password"] ?? "secret123"
  );
  await user.click(
    screen.getByRole("button", { name: /set new password/i })
  );
}

describe("UpdatePasswordForm rendering and validation", () => {
  it("renders password and confirmation fields", () => {
    render(<UpdatePasswordForm />);
    expect(screen.getByLabelText("New password")).toBeTruthy();
    expect(screen.getByLabelText("Confirm new password")).toBeTruthy();
  });

  it("rejects short new passwords without calling the provider", async () => {
    render(<UpdatePasswordForm />);
    await fillAndSubmit({ "New password": "abc", "Confirm new password": "abc" });
    expect(await screen.findByText(/at least \d+ characters/i)).toBeTruthy();
    expect(updateUserMock).not.toHaveBeenCalled();
  });

  it("rejects a confirmation mismatch without calling the provider", async () => {
    render(<UpdatePasswordForm />);
    await fillAndSubmit({ "Confirm new password": "different456" });
    expect(await screen.findByText(/do not match/i)).toBeTruthy();
    expect(updateUserMock).not.toHaveBeenCalled();
  });
});

describe("UpdatePasswordForm success handling", () => {
  it("sets the new password securely and shows a success message", async () => {
    updateUserMock.mockResolvedValue({ data: { user: { id: "u1" } }, error: null });
    render(<UpdatePasswordForm />);
    await fillAndSubmit();

    await waitFor(() => {
      expect(updateUserMock).toHaveBeenCalledWith({ password: "secret123" });
    });
    const status = await screen.findByRole("status");
    expect(status.textContent).toContain("Password updated");
    expect(screen.getByRole("link", { name: /continue to sign in/i }).getAttribute("href")).toBe("/login");
  });

  it("shows a safe error and keeps the form when the update fails", async () => {
    updateUserMock.mockResolvedValue({
      data: { user: null },
      error: { message: "some internal credential trace" },
    });
    render(<UpdatePasswordForm />);
    await fillAndSubmit();

    expect(
      await screen.findByText(/reset link may have expired/i)
    ).toBeTruthy();
    // Provider internals must not be echoed back.
    expect(screen.queryByText(/credential trace/i)).toBeNull();
    expect(
      screen.getByRole("button", { name: /set new password/i })
    ).toBeTruthy();
  });
});
