import { describe, expect, it } from "vitest";
import { senderAuthLabel } from "./SpoofWarning";

describe("senderAuthLabel", () => {
  it("does not describe an unknown result as authenticated", () => {
    expect(senderAuthLabel({})).toBe("Authentication status unavailable");
    expect(senderAuthLabel({ auth_status: "missing" })).toBe("SPF, DKIM, and DMARC results unavailable");
  });

  it("distinguishes authenticated and suspicious senders", () => {
    expect(senderAuthLabel({ auth_status: "authenticated" })).toBe("Authenticated");
    expect(senderAuthLabel({ auth_status: "suspected_spoof" })).toBe("Authentication failed or suspicious");
  });
});
