import { EmailClient, type EmailMessage } from "@azure/communication-email";
import type { AppEnv } from "../config/env.js";

type Template = "email-verification" | "password-reset" | "email-change-code";

export type EmailDeliveryInput = {
  to: string;
  token: string;
  correlationId: string;
};

export interface EmailProvider {
  sendVerificationEmail(input: EmailDeliveryInput): Promise<void>;
  sendResetPasswordEmail(input: EmailDeliveryInput): Promise<void>;
  sendEmailChangeCode(input: EmailDeliveryInput): Promise<void>;
}

type EmailSendPoller = {
  pollUntilDone(): Promise<unknown>;
};

type EmailClientLike = {
  beginSend(message: EmailMessage): Promise<EmailSendPoller>;
};

type AzureAcsEmailProviderOptions = {
  connectionString: string;
  senderAddress: string;
  verifyPageUrl: string;
  resetPageUrl: string;
  replyToAddress?: string;
  sendTimeoutMs?: number;
  maxAttempts?: number;
  retryBaseDelayMs?: number;
  emailClient?: EmailClientLike;
};

export class ConsoleEmailProvider implements EmailProvider {
  async sendVerificationEmail(input: EmailDeliveryInput): Promise<void> {
    this.log("email-verification", input);
  }

  async sendResetPasswordEmail(input: EmailDeliveryInput): Promise<void> {
    this.log("password-reset", input);
  }

  async sendEmailChangeCode(input: EmailDeliveryInput): Promise<void> {
    this.log("email-change-code", input);
  }

  private log(template: Template, input: EmailDeliveryInput): void {
    // eslint-disable-next-line no-console
    console.info(`[auth-email:${template}]`, {
      to: input.to,
      correlationId: input.correlationId,
      tokenPreview: `${input.token.slice(0, 6)}...`,
    });
  }
}

export class FallbackEmailProvider implements EmailProvider {
  constructor(
    private readonly primary: EmailProvider,
    private readonly fallback: EmailProvider,
    private readonly fallbackTag: string,
  ) {}

  async sendVerificationEmail(input: EmailDeliveryInput): Promise<void> {
    await this.sendWithFallback("email-verification", input, () =>
      this.primary.sendVerificationEmail(input),
    );
  }

  async sendResetPasswordEmail(input: EmailDeliveryInput): Promise<void> {
    await this.sendWithFallback("password-reset", input, () =>
      this.primary.sendResetPasswordEmail(input),
    );
  }

  async sendEmailChangeCode(input: EmailDeliveryInput): Promise<void> {
    await this.sendWithFallback("email-change-code", input, () =>
      this.primary.sendEmailChangeCode(input),
    );
  }

  private async sendWithFallback(
    template: Template,
    input: EmailDeliveryInput,
    sendPrimary: () => Promise<void>,
  ): Promise<void> {
    try {
      await sendPrimary();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.warn("[auth-email:fallback-console]", {
        template,
        to: input.to,
        correlationId: input.correlationId,
        tag: this.fallbackTag,
        message: errorMessage(error),
      });
      if (template === "email-verification") {
        await this.fallback.sendVerificationEmail(input);
        return;
      }
      if (template === "password-reset") {
        await this.fallback.sendResetPasswordEmail(input);
        return;
      }
      if (template === "email-change-code") {
        await this.fallback.sendEmailChangeCode(input);
        return;
      }
    }
  }
}

export class AzureAcsEmailProvider implements EmailProvider {
  private readonly emailClient: EmailClientLike;
  private readonly senderAddress: string;
  private readonly replyToAddress: string | undefined;
  private readonly verifyPageUrl: string;
  private readonly resetPageUrl: string;
  private readonly sendTimeoutMs: number;
  private readonly maxAttempts: number;
  private readonly retryBaseDelayMs: number;

  constructor(options: AzureAcsEmailProviderOptions) {
    this.emailClient = options.emailClient ?? new EmailClient(options.connectionString);
    this.senderAddress = options.senderAddress;
    this.replyToAddress = options.replyToAddress;
    this.verifyPageUrl = options.verifyPageUrl;
    this.resetPageUrl = options.resetPageUrl;
    this.sendTimeoutMs = options.sendTimeoutMs ?? 10_000;
    this.maxAttempts = options.maxAttempts ?? 3;
    this.retryBaseDelayMs = options.retryBaseDelayMs ?? 250;
  }

  async sendVerificationEmail(input: EmailDeliveryInput): Promise<void> {
    await this.sendWithRetry("email-verification", input);
  }

  async sendResetPasswordEmail(input: EmailDeliveryInput): Promise<void> {
    await this.sendWithRetry("password-reset", input);
  }

  async sendEmailChangeCode(input: EmailDeliveryInput): Promise<void> {
    await this.sendWithRetry("email-change-code", input);
  }

  private async sendWithRetry(template: Template, input: EmailDeliveryInput): Promise<void> {
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        await this.sendOnce(template, input);
        return;
      } catch (error) {
        if (attempt >= this.maxAttempts) {
          throw error;
        }
        const waitMs = this.retryBaseDelayMs * 2 ** (attempt - 1);
        // eslint-disable-next-line no-console
        console.warn("[auth-email:retry]", {
          template,
          to: input.to,
          correlationId: input.correlationId,
          attempt,
          nextDelayMs: waitMs,
          message: errorMessage(error),
        });
        await delay(waitMs);
      }
    }
  }

  private async sendOnce(template: Template, input: EmailDeliveryInput): Promise<void> {
    const message = this.buildMessage(template, input);
    const startedAt = Date.now();
    const poller = await withTimeout(
      this.emailClient.beginSend(message),
      this.sendTimeoutMs,
      `Azure ACS beginSend timeout after ${this.sendTimeoutMs}ms`,
    );
    const elapsedMs = Date.now() - startedAt;
    const remainingTimeoutMs = Math.max(250, this.sendTimeoutMs - elapsedMs);
    const result = await withTimeout(
      poller.pollUntilDone(),
      remainingTimeoutMs,
      `Azure ACS email timeout after ${this.sendTimeoutMs}ms`,
    );
    const status = readStatus(result);
    if (status !== "succeeded") {
      throw new Error(`Azure ACS email send failed with status=${status ?? "unknown"}`);
    }
  }

  private buildMessage(template: Template, input: EmailDeliveryInput): EmailMessage {
    const data = this.buildTemplateData(template, input.token);
    return {
      senderAddress: this.senderAddress,
      content: {
        subject: data.subject,
        plainText: data.plainText,
        html: data.html,
      },
      recipients: {
        to: [
          {
            address: input.to,
          },
        ],
      },
      ...(this.replyToAddress
        ? {
            replyTo: [
              {
                address: this.replyToAddress,
              },
            ],
          }
        : {}),
      headers: {
        "x-correlation-id": input.correlationId,
      },
    };
  }

  private buildTemplateData(template: Template, token: string): {
    subject: string;
    plainText: string;
    html: string;
  } {
    const encodedToken = encodeURIComponent(token);

    if (template === "email-verification") {
      const verificationUrl = buildUrlWithToken(this.verifyPageUrl, encodedToken);
      return {
        subject: "Sigfarm - Verifique seu email",
        plainText: [
          "Confirme seu email para concluir o cadastro.",
          `Link: ${verificationUrl}`,
          `Token: ${token}`,
        ].join("\n"),
        html: [
          "<p>Confirme seu email para concluir o cadastro.</p>",
          `<p><a href="${verificationUrl}">Verificar email</a></p>`,
          `<p>Se preferir, use este token: <code>${escapeHtml(token)}</code></p>`,
        ].join(""),
      };
    }

    const resetUrl = buildUrlWithToken(this.resetPageUrl, encodedToken);
    if (template === "password-reset") {
      return {
        subject: "Sigfarm - Redefinição de senha",
        plainText: [
          "Recebemos um pedido para redefinir sua senha.",
          `Link: ${resetUrl}`,
          `Token: ${token}`,
        ].join("\n"),
        html: [
          "<p>Recebemos um pedido para redefinir sua senha.</p>",
          `<p><a href="${resetUrl}">Redefinir senha</a></p>`,
          `<p>Se preferir, use este token: <code>${escapeHtml(token)}</code></p>`,
        ].join(""),
      };
    }

    return {
      subject: "Sigfarm - Codigo para alterar email",
      plainText: [
        "Use o codigo abaixo para confirmar a troca de email da sua conta.",
        `Codigo: ${token}`,
        "Se voce nao solicitou esta alteracao, ignore esta mensagem.",
      ].join("\n"),
      html: [
        "<p>Use o codigo abaixo para confirmar a troca de email da sua conta.</p>",
        `<p><strong style="font-size:20px;letter-spacing:0.12em">${escapeHtml(token)}</strong></p>`,
        "<p>Se voce nao solicitou esta alteracao, ignore esta mensagem.</p>",
      ].join(""),
    };
  }
}

export function createEmailProvider(env: AppEnv): EmailProvider {
  const isDevLike = env.nodeEnv === "development" || env.nodeEnv === "test";
  const selectedProvider = env.emailProvider ?? (isDevLike ? "console" : undefined);

  if (selectedProvider === "console") {
    return new ConsoleEmailProvider();
  }

  if (selectedProvider === "azure-acs") {
    const missingRequiredVars = [
      !env.acsEmailConnectionString ? "ACS_EMAIL_CONNECTION_STRING" : null,
      !env.acsEmailSender ? "ACS_EMAIL_SENDER" : null,
    ].filter((item): item is string => item !== null);

    if (missingRequiredVars.length > 0) {
      if (isDevLike) {
        // eslint-disable-next-line no-console
        console.warn("[auth-email:fallback-console]", {
          reason: "Azure ACS provider configured with missing variables",
          missing: missingRequiredVars,
          nodeEnv: env.nodeEnv,
        });
        return new ConsoleEmailProvider();
      }
      throw new Error(
        `EMAIL_PROVIDER=azure-acs requires ${missingRequiredVars.join(", ")}`,
      );
    }
    const connectionString = env.acsEmailConnectionString;
    const senderAddress = env.acsEmailSender;
    if (!connectionString || !senderAddress) {
      throw new Error("Invalid Azure ACS email provider configuration");
    }
    const azureProvider = new AzureAcsEmailProvider({
      connectionString,
      senderAddress,
      ...(env.acsEmailReplyTo ? { replyToAddress: env.acsEmailReplyTo } : {}),
      verifyPageUrl: env.authEmailVerifyPageUrl,
      resetPageUrl: env.authEmailResetPageUrl,
      sendTimeoutMs: isDevLike ? Math.min(env.authEmailSendTimeoutMs, 5_000) : env.authEmailSendTimeoutMs,
      maxAttempts: isDevLike ? 1 : env.authEmailRetryAttempts,
      retryBaseDelayMs: env.authEmailRetryBaseDelayMs,
    });

    if (isDevLike) {
      return new FallbackEmailProvider(
        azureProvider,
        new ConsoleEmailProvider(),
        "dev-or-test-azure-acs",
      );
    }
    return azureProvider;
  }

  throw new Error("Transactional email provider not configured for production-like environment");
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((error: unknown) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

function readStatus(result: unknown): string | undefined {
  if (!result || typeof result !== "object") return undefined;
  const value = (result as { status?: unknown }).status;
  if (typeof value !== "string") return undefined;
  return value.toLowerCase();
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function buildUrlWithToken(baseUrl: string, encodedToken: string): string {
  const url = new URL(baseUrl);
  url.searchParams.set("token", encodedToken);
  return url.toString();
}
