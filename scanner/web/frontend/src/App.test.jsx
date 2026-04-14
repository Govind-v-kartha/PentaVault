import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import App from "./App";

const fetchMock = vi.fn(async (url) => {
  if (String(url).includes("/api/frontend/mode")) {
    return {
      ok: true,
      text: async () => JSON.stringify({ selected_mode: "legacy", active_mode: "legacy", available_modes: ["legacy"] }),
    };
  }
  if (String(url).includes("/api/scans")) {
    return { ok: true, text: async () => "[]" };
  }
  if (String(url).includes("/api/owasp")) {
    return { ok: true, text: async () => JSON.stringify({ "A01:2025": "Broken Access Control" }) };
  }
  if (String(url).includes("/api/mitre/tactics")) {
    return { ok: true, text: async () => "[]" };
  }
  if (String(url).includes("/api/mitre")) {
    return { ok: true, text: async () => "{}" };
  }
  return { ok: true, text: async () => "{}" };
});

vi.stubGlobal("fetch", fetchMock);

afterEach(() => {
  cleanup();
  fetchMock.mockClear();
});

describe("App", () => {
  it("renders dashboard heading", async () => {
    render(<App />);
    expect(await screen.findByText(/PentaVault Mission Dashboard/i)).toBeInTheDocument();
  });

  it("renders reference dataset metrics", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /OWASP \/ MITRE/i }));
    expect(await screen.findByText(/Reference Datasets/i)).toBeInTheDocument();
  });
});
