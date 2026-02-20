import { describe, expect, it } from "vitest";
import { mapMicrosoftProfileToUser } from "../src/auth/microsoft-profile.js";

describe("microsoft profile mapping", () => {
  it("marks microsoft emails as verified when email is present", () => {
    const mapped = mapMicrosoftProfileToUser({
      email: "user@sigfarm.com",
    });

    expect(mapped).toEqual({
      emailVerified: true,
    });
  });

  it("does not force verification without a usable email", () => {
    const mapped = mapMicrosoftProfileToUser({
      email: "   ",
    });

    expect(mapped).toEqual({});
  });
});
