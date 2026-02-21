import { describe, expect, it } from "vitest";
import { readTokenFromLocation, readTokenFromQuery } from "../lib/token-query";

describe("readTokenFromQuery", () => {
  it("reads token from lowercase key", () => {
    expect(readTokenFromQuery({ token: "abc" })).toBe("abc");
  });

  it("reads token from uppercase fallback key", () => {
    expect(readTokenFromQuery({ Token: "abc" })).toBe("abc");
  });

  it("decodes previously double-encoded token once", () => {
    expect(readTokenFromQuery({ token: "ab%2Bc%2F%3D%3D" })).toBe("ab+c/==");
  });

  it("returns raw value when decode fails", () => {
    expect(readTokenFromQuery({ token: "%E0%A4%A" })).toBe("%E0%A4%A");
  });

  it("normalizes spaces to plus when query token parser returns spaces", () => {
    expect(readTokenFromQuery({ token: "ab c/==" })).toBe("ab+c/==");
  });

  it("prefers raw location search token when available", () => {
    const value = readTokenFromLocation({ token: "ab c/==" }, "?token=ab+c%2F%3D%3D");
    expect(value).toBe("ab+c/==");
  });
});
