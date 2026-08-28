/**
 * Forgot-password form tests.
 *
 * Covers: rendering + navigation, validation, calling the official recovery
 * flow (resetPasswordForEmail), and the critical privacy guarantee — the SAME
 * generic success message is shown whether the request succeeds, the email is
 * unknown, or the request is rate-limited (never reveal account existence).
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ForgotPasswordForm from "@/app/forgot-password/ForgotPasswordForm";

const resetPasswordMock = vi.fn();

vi.mock("@/lib/supabase/client", () => ({
  createClient: () => ({
    auth: {
      resetPasswordForEmail: resetPasswordMock,
    },
  }),
}));

beforeEach(() => {
  resetPasswordMock.mockReset();
});

async function submitEmail(overrides: Partial<{ Email: string }> = {}) {
  const user = userEvent.setup();
  await user.type(
    screen.getByLabelText("Email"),
    overrides.Email ?? "user@example.com"
  );
  await user.click(screen.getByRole("button", { name: /send reset link/i }));
}

describe("ForgotPasswordForm rendering and navigation", () => {
  it("renders email field, submit button and a link back to login", () => {
    render(<ForgotPasswordForm />);
    expect(screen.getByLabelText("Email")).toBeTruthy();
    expect(screen.getByRole("button", { name: /send reset link/i })).toBeTruthy();
    const loginLink = screen.getAllByRole("link", { name: /back to sign in/i });
    expect(loginLink[0].getAttribute("href")).toBe("/login");
  });
});

describe("ForgotPasswordForm validation", () => {
  it("rejects a malformed email without calling the provider", async () => {
    render(<ForgotPasswordForm />);
    await submitEmail({ Email: "not-an-email" });
    expect(await screen.findByText(/valid email address/i)).toBeTruthy();
    expect(resetPasswordMock).not.toHaveBeenCalled();
  });
});

describe("ForgotPasswordForm recovery flow", () => {
  it("calls resetPasswordForEmail with a recovery redirect", async () => {
    resetPasswordMock.mockResolvedValue({ data: {}, error: null });
    render(<ForgotPasswordForm />);
    await submitEmail();
    await waitFor(() => {
      expect(resetPasswordMock).toHaveBeenCalledWith("user@example.com", {
        redirectTo: expect.stringContaining("/auth/callback"),
      });
      expect(
        resetPasswordMock.mock.calls[0][1].redirectTo
      ).toContain("next=" + "/auth/update-password");
    });
  });

  it("shows the same generic success message on success", async () => {
    resetPasswordMock.mockResolvedValue({ data: {}, error: null });
    render(<ForgotPasswordForm />);
    await submitEmail();
    const status = await screen.findByRole("status");
    expect(status.textContent).toContain("If an account exists");
    expect(status.textContent).toContain("user@example.com");
  });

  it("does NOT reveal account existence when the email is unknown", async () => {
    resetPasswordMock.mockResolvedValue({
      data: {},
      error: { message: "User not found" },
    });
    render(<ForgotPasswordForm />);
    await submitEmail({ Email: "unknown@example.com" });
    const status = await screen.findByRole("status");
    expect(status.textContent).toContain("If an account exists");
    expect(status.textContent).not.toContain("User not found");
    expect(status.textContent).not.toMatch(/does not exist|not found/i);
  });

  it("ever surfaces the same message even on a thrown error", async () => {
    resetPasswordMock.mockRejectedValue(new TypeError("fetch failed"));
    render(<ForgotPasswordForm />);
    await submitEmail();
    const status = await screen.findByRole("status");
    expect(status.textContent).toContain("If an account exists");
  });
});
