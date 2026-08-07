import { describe, expect, it } from "vitest";
import { formatReportDay } from "./date";

describe("formatReportDay", () => {
  it("does not shift a UTC report bucket into the previous local day", () => {
    expect(formatReportDay("2026-07-29T00:00:00Z", "en-US")).toBe("7/29/2026");
  });

  it("returns invalid values unchanged", () => {
    expect(formatReportDay("not-a-date", "en-US")).toBe("not-a-date");
  });
});
