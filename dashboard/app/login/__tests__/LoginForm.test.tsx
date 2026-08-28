/**
 * Login form regression tests — sign-in still works and offers navigation
 * to the signup page.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import LoginForm from "@/app/login/LoginForm";

const signInMock = vi.fn();
const replaceMock = vi.fn();
const navigateToMock = vi.fn();

vi.mock("@/lib/supabase/client", () => ({
  createClient: () => ({
    auth: {
      signInWithPassword: signInMock,
    },
  }),
}));

vi.mock("@/lib/navigate", () => ({
  navigateTo: (path: string) => navigateToMock(path),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

beforeEach(() => {
  signInMock.mockReset();
  replaceMock.mockReset();
  navigateToMock.mockReset();
});

describe("LoginForm navigation", () => {
  it("links to the signup page", () => {
    render(<LoginForm />);
    const link = screen.getByRole("link", { name: "Sign up" });
    expect(link.getAttribute("href")).toBe("/signup");
  });

  it("links to the forgot-password page", () => {
    render(<LoginForm />);
    const link = screen.getByRole("link", { name: /forgot password/i });
    expect(link.getAttribute("href")).toBe("/forgot-password");
  });
});

describe("LoginForm regression", () => {
  it("signs in with valid credentials and redirects to /dashboard", async () => {
    signInMock.mockResolvedValue({ data: { session: {} }, error: null });
    const user = userEvent.setup();
    render(<LoginForm />);

    await user.type(screen.getByLabelText("Email"), "user@example.com");
    await user.type(screen.getByLabelText("Password"), "secret123");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(signInMock).toHaveBeenCalledWith({
        email: "user@example.com",
        password: "secret123",
      });
      expect(navigateToMock).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("shows a generic message on bad credentials without redirecting", async () => {
    signInMock.mockResolvedValue({
      data: { session: null },
      error: { message: "Invalid login credentials" },
    });
    const user = userEvent.setup();
    render(<LoginForm />);

    await user.type(screen.getByLabelText("Email"), "user@example.com");
    await user.type(screen.getByLabelText("Password"), "wrongpass");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(
      await screen.findByText(/invalid email or password/i)
    ).toBeTruthy();
    expect(navigateToMock).not.toHaveBeenCalled();
  });
});
