/**
 * 404 page tests — must clearly say the page doesn't exist and link back
 * to the dashboard, without exposing internals.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import NotFound from "@/app/not-found";

describe("NotFound (404)", () => {
  it("states that the page does not exist", () => {
    render(<NotFound />);
    expect(screen.getByText("This page doesn't exist")).toBeTruthy();
    expect(
      screen.getByText(/moved, removed, or never existed/i)
    ).toBeTruthy();
  });

  it("links back to the dashboard", () => {
    render(<NotFound />);
    const link = screen.getByRole("link", { name: "Back to dashboard" });
    expect(link.getAttribute("href")).toBe("/dashboard");
  });

  it("does not render stack traces or internal identifiers", () => {
    const { container } = render(<NotFound />);
    expect(container.textContent).not.toMatch(/at .+:\d+/);
    expect(container.textContent).not.toMatch(/traceback|exception/i);
  });
});
