/**
 * Signup form behaviour tests.
 *
 * Covers: field rendering + navigation, client-side validation (mismatch,
 * short password, bad email), successful signup with an immediate session
 * (redirect to /dashboard), confirmation-required messaging without a
 * redirect, and safe provider-error mapping.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SignupForm, { mapSignupError } from "@/app/signup/SignupForm";

const signUpMock = vi.fn();
const navigateToMock = vi.fn();

vi.mock("@/lib/supabase/client", () => ({
  createClient: () => ({
    auth: {
      signUp: signUpMock,
    },
  }),
}));

vi.mock("@/lib/navigate", () => ({
  navigateTo: (path: string) => navigateToMock(path),
}));

function typeInto(
  label: string,
  value: string,
  user: ReturnType<typeof userEvent.setup>
) {
  return user.type(screen.getByLabelText(label), value);
}

beforeEach(() => {
  signUpMock.mockReset();
  navigateToMock.mockReset();
});

async function fillAndSubmit(
  user: ReturnType<typeof userEvent.setup>,
  overrides: Partial<Record<"Email" | "Password" | "Confirm password", string>> = {}
) {
  await typeInto("Email", overrides.Email ?? "new.user@example.com", user);
  await typeInto("Password", overrides.Password ?? "secret123", user);
  await typeInto("Confirm password", overrides["Confirm password"] ?? "secret123", user);
  await user.click(screen.getByRole("button", { name: /create account/i }));
}

describe("SignupForm rendering and navigation", () => {
  it("renders email, password and confirmation fields", () => {
    render(<SignupForm />);
    expect(screen.getByLabelText("Email")).toBeTruthy();
    expect(screen.getByLabelText("Password")).toBeTruthy();
    expect(screen.getByLabelText("Confirm password")).toBeTruthy();
    expect(
      screen.getByRole("button", { name: /create account/i })
    ).toBeTruthy();
  });

  it("links back to the login page", () => {
    render(<SignupForm />);
    const link = screen.getByRole("link", { name: "Log in" });
    expect(link.getAttribute("href")).toBe("/login");
  });
});

describe("SignupForm validation", () => {
  it("rejects mismatched passwords without calling the provider", async () => {
    const user = userEvent.setup();
    render(<SignupForm />);
    await fillAndSubmit(user, { "Confirm password": "different456" });

    expect(await screen.findByText(/do not match/i)).toBeTruthy();
    expect(signUpMock).not.toHaveBeenCalled();
  });

  it("rejects too-short passwords without calling the provider", async () => {
    const user = userEvent.setup();
    render(<SignupForm />);
    await fillAndSubmit(user, { Password: "abc", "Confirm password": "abc" });

    expect(
      await screen.findByText(/at least \d+ characters/i)
    ).toBeTruthy();
    expect(signUpMock).not.toHaveBeenCalled();
  });

  it("rejects malformed emails without calling the provider", async () => {
    const user = userEvent.setup();
    render(<SignupForm />);
    await fillAndSubmit(user, { Email: "not-an-email" });

    expect(
      await screen.findByText(/valid email address/i)
    ).toBeTruthy();
    expect(signUpMock).not.toHaveBeenCalled();
  });
});

describe("SignupForm success handling", () => {
  it("redirects to /dashboard when a session is returned immediately", async () => {
    signUpMock.mockResolvedValue({
      data: { session: { access_token: "x" }, user: { id: "u1" } },
      error: null,
    });
    const user = userEvent.setup();
    render(<SignupForm />);
    await fillAndSubmit(user);

    await waitFor(() => {
      expect(signUpMock).toHaveBeenCalledWith({
        email: "new.user@example.com",
        password: "secret123",
      });
      expect(navigateToMock).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("shows a check-your-email message when confirmation is required", async () => {
    signUpMock.mockResolvedValue({ data: { session: null, user: null }, error: null });
    const user = userEvent.setup();
    render(<SignupForm />);
    await fillAndSubmit(user, { Email: "confirm.me@example.com" });

    const status = await screen.findByRole("status");
    expect(status.textContent).toContain("Account created");
    expect(status.textContent).toContain("confirmation link");
    expect(status.textContent).toContain("confirm.me@example.com");
    // Must NOT pretend the user is authenticated.
    expect(navigateToMock).not.toHaveBeenCalled();
    // Offers a path onward to sign in.
    expect(screen.getByRole("link", { name: "Sign in" })).toBeTruthy();
  });
});

describe("SignupForm provider errors", () => {
  it.each([
    ["User already registered", /already exists.*signing in/i],
    ["Password should be at least 10 characters.", /^Password should be at least 10 characters\.$/],
    ["Rate limit exceeded", /too many signup attempts/i],
    ["Something internal exploded at /internal/trace", /could not create your account/i],
  ])("maps %s to a safe message", async (providerMessage, expected) => {
    signUpMock.mockResolvedValue({
      data: { session: null, user: null },
      error: { message: providerMessage },
    });
    const user = userEvent.setup();
    render(<SignupForm />);
    await fillAndSubmit(user);

    expect(await screen.findByText(expected)).toBeTruthy();
    expect(navigateToMock).not.toHaveBeenCalled();
  });

  it("maps thrown network failures to a connection message", async () => {
    signUpMock.mockRejectedValue(new TypeError("fetch failed"));
    const user = userEvent.setup();
    render(<SignupForm />);
    await fillAndSubmit(user);

    expect(
      await screen.findByText(/could not reach the authentication service/i)
    ).toBeTruthy();
  });
});

describe("mapSignupError", () => {
  it("never echoes unknown provider internals", () => {
    const msg = mapSignupError("stack trace with secret-host.internal:5432");
    expect(msg).toMatch(/could not create your account/i);
    expect(msg).not.toContain("secret-host");
  });
});
