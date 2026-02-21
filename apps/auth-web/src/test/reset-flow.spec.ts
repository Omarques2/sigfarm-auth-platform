import { describe, expect, it } from "vitest";
import {
  getResetProgressLabel,
  getResendLabel,
  getResetRequestNotice,
  getResetRequestCountdownSeconds,
} from "../lib/reset-flow";

describe("reset-flow helpers", () => {
  it("returns generic notice for sent status", () => {
    expect(getResetRequestNotice("sent")).toBe(
      "Se o e-mail informado estiver cadastrado, enviaremos um código de verificação.",
    );
  });

  it("returns generic notice for cooldown status", () => {
    expect(getResetRequestNotice("cooldown")).toBe(
      "Se o e-mail informado estiver cadastrado, enviaremos um código de verificação.",
    );
  });

  it("normalizes resend countdown to at least 1 second", () => {
    expect(getResetRequestCountdownSeconds(0)).toBe(60);
    expect(getResetRequestCountdownSeconds(-5)).toBe(60);
    expect(getResetRequestCountdownSeconds(2)).toBe(2);
  });

  it("formats resend labels with countdown suffix", () => {
    expect(getResendLabel("codigo", 53)).toBe("Reenviar código (53s)");
    expect(getResendLabel("email", 12)).toBe("Reenviar e-mail (12s)");
  });

  it("formats resend labels without countdown", () => {
    expect(getResendLabel("codigo", 0)).toBe("Reenviar código");
    expect(getResendLabel("email", 0)).toBe("Reenviar e-mail");
  });

  it("returns reset progress labels by step", () => {
    expect(getResetProgressLabel("reset-code")).toBe("Etapa 1 de 2");
    expect(getResetProgressLabel("reset-password")).toBe("Etapa 2 de 2");
  });
});
