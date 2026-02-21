export type ResetRequestStatus = "sent" | "cooldown";
export type ResetStep = "reset-code" | "reset-password";

const GENERIC_RESET_NOTICE = "Se o e-mail informado estiver cadastrado, enviaremos um código de verificação.";
const DEFAULT_RESEND_SECONDS = 60;

export function getResetRequestNotice(_status: ResetRequestStatus): string {
  return GENERIC_RESET_NOTICE;
}

export function getResetRequestCountdownSeconds(retryAfterSeconds: number): number {
  if (!Number.isFinite(retryAfterSeconds) || retryAfterSeconds <= 0) {
    return DEFAULT_RESEND_SECONDS;
  }

  return Math.max(1, Math.floor(retryAfterSeconds));
}

export function getResendLabel(kind: "codigo" | "email", seconds: number): string {
  const base = kind === "email" ? "Reenviar e-mail" : "Reenviar código";
  return seconds > 0 ? `${base} (${seconds}s)` : base;
}

export function getResetProgressLabel(step: ResetStep): string {
  return step === "reset-code" ? "Etapa 1 de 2" : "Etapa 2 de 2";
}

export function getResetResendHint(): string {
  return "Não recebeu o e-mail? Verifique o spam e a lixeira.";
}
