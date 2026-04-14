import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import ResultsPanel from "./ResultsPanel";

describe("ResultsPanel", () => {
  it("shows title-first findings when type/module fields are absent", () => {
    const scan = {
      target: "https://example.com",
      mode: "quick",
      status: "completed",
      progress: 100,
      elapsed: 12,
      findings_count: 1,
      summary: { Medium: 1 },
      findings: [
        {
          title: "Missing Content-Security-Policy (CSP) on /",
          affected_url: "https://example.com",
          remediation: "Set a restrictive Content-Security-Policy header.",
          severity: "Medium",
        },
      ],
    };

    render(
      <ResultsPanel
        scan={scan}
        loading={false}
        onAiAnalyze={vi.fn()}
        onAiExecutiveSummary={vi.fn()}
        onAiRemediate={vi.fn()}
        aiState={{}}
      />,
    );

    expect(screen.getByText(/missing content-security-policy/i)).toBeInTheDocument();
    expect(screen.getByText("https://example.com")).toBeInTheDocument();
    expect(screen.getByText(/content-security-policy header/i)).toBeInTheDocument();
  });

  it("shows active remediation marker and empty-filter state", () => {
    const scan = {
      target: "https://example.com",
      mode: "quick",
      status: "completed",
      progress: 100,
      elapsed: 12,
      findings_count: 1,
      summary: { Medium: 1 },
      findings: [
        {
          title: "Missing X-Frame-Options",
          affected_url: "https://example.com",
          remediation: "Set X-Frame-Options: DENY",
          severity: "Medium",
        },
      ],
    };

    render(
      <ResultsPanel
        scan={scan}
        loading={false}
        onAiAnalyze={vi.fn()}
        onAiExecutiveSummary={vi.fn()}
        onAiRemediate={vi.fn()}
        aiState={{ remediationFindingIndex: 0 }}
      />,
    );

    expect(screen.getByRole("button", { name: /AI Remediate \(active\)/i })).toBeInTheDocument();
  });
});
