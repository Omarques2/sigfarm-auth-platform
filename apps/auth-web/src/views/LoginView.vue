<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { authWebEnv } from "../config/env";
import { authApiClient, AuthApiError } from "../lib/auth-api";
import { resolveSafeReturnTo } from "../lib/return-to";

type LoginStep = "email" | "password" | "signup" | "verify-pending" | "reset-code" | "reset-password";
type Rule = { key: string; label: string; met: boolean };

const route = useRoute();
const router = useRouter();

const step = ref<LoginStep>("email");
const flashError = ref<string | null>(null);
const flashSuccess = ref<string | null>(null);
const isCallbackProcessing = ref(false);
const isCallbackInFlight = ref(false);

const emailValue = ref("");
const passwordValue = ref("");
const signupName = ref("");
const signupPassword = ref("");
const showPasswordField = ref(false);
const showSignupPasswordField = ref(false);
const showResetPasswordField = ref(false);

const isEmailSubmitting = ref(false);
const isPasswordSubmitting = ref(false);
const isSignupSubmitting = ref(false);
const isMicrosoftSubmitting = ref(false);

const verification = reactive({ email: "", notice: "", error: "", resendSeconds: 0, isSending: false });
const resetFlow = reactive({
  email: "",
  notice: "",
  error: "",
  resendSeconds: 0,
  isRequesting: false,
  isVerifying: false,
  isCompleting: false,
  codeDigits: ["", "", "", "", "", ""] as string[],
  newPassword: "",
});

let verificationTimer: ReturnType<typeof setInterval> | null = null;
let resetTimer: ReturnType<typeof setInterval> | null = null;
const resetRefs = ref<Array<HTMLInputElement | null>>([]);

const normalizedEmail = computed(() => normalizeEmail(emailValue.value));
const resetCode = computed(() => resetFlow.codeDigits.join(""));
const safeReturnTo = computed(() =>
  resolveSafeReturnTo(
    withOptionalReferrer({
      returnTo: firstQueryValue(route.query.returnTo),
      appBaseUrl: authWebEnv.authWebBaseUrl,
      defaultReturnTo: authWebEnv.defaultReturnTo,
      allowedOrigins: authWebEnv.allowedReturnOrigins,
    }),
  ),
);
const callbackUrl = computed(() => {
  const url = new URL("/auth/callback", authWebEnv.authWebBaseUrl);
  url.searchParams.set("returnTo", safeReturnTo.value);
  return url.toString();
});
const signupRules = computed(() => passwordRules(signupPassword.value));
const signupStrong = computed(() => signupRules.value.every((rule) => rule.met));
const showSignupChecklist = computed(() => signupPassword.value.trim().length > 0);
const resetRules = computed(() => passwordRules(resetFlow.newPassword));
const resetStrong = computed(() => resetRules.value.every((rule) => rule.met));
const showResetChecklist = computed(() => resetFlow.newPassword.trim().length > 0);
const shouldShowSocial = computed(
  () => (step.value === "email" || step.value === "password") && !isCallbackProcessing.value,
);
const globalFeedback = computed(() =>
  flashError.value
    ? { type: "error" as const, message: flashError.value }
    : flashSuccess.value
      ? { type: "success" as const, message: flashSuccess.value }
      : null,
);
const verificationFeedback = computed(() =>
  verification.error
    ? { type: "error" as const, message: verification.error }
    : verification.notice
      ? { type: "success" as const, message: verification.notice }
      : null,
);
const resetFeedback = computed(() =>
  resetFlow.error
    ? { type: "error" as const, message: resetFlow.error }
    : resetFlow.notice
      ? { type: "success" as const, message: resetFlow.notice }
      : null,
);

onMounted(async () => {
  applyStatusFromQuery();
  await maybeHandleCallback();
  if (!isCallbackRoute()) await tryResumeSession();
});
watch(
  () => route.fullPath,
  async () => {
    applyStatusFromQuery();
    await maybeHandleCallback();
  },
);
onBeforeUnmount(() => {
  stopVerificationCountdown();
  stopResetCountdown();
});

function isCallbackRoute(): boolean {
  return route.name === "auth-callback" || route.path === "/auth/callback";
}

async function maybeHandleCallback(): Promise<void> {
  if (!isCallbackRoute()) {
    isCallbackProcessing.value = false;
    return;
  }
  if (isCallbackInFlight.value) return;
  isCallbackInFlight.value = true;
  isCallbackProcessing.value = true;
  clearFlash();
  try {
    const error = firstQueryValue(route.query.error);
    const errorDescription = firstQueryValue(route.query.error_description);
    if (error || errorDescription) {
      flashError.value = "Nao foi possivel concluir o login com Microsoft. Tente novamente.";
      await router.replace({ name: "login", query: { status: "callback-error", returnTo: safeReturnTo.value } });
      return;
    }
    const session = await authApiClient.getSession();
    if (!session) {
      flashError.value = "Sessao de autenticacao nao encontrada. Tente novamente.";
      await router.replace({ name: "login", query: { status: "session-missing", returnTo: safeReturnTo.value } });
      return;
    }
    await authApiClient.exchangeSession();
    window.location.assign(safeReturnTo.value);
  } catch (error) {
    flashError.value = resolveAuthError(error).message;
    if (isCallbackRoute()) await router.replace({ name: "login", query: { returnTo: safeReturnTo.value } });
  } finally {
    isCallbackProcessing.value = false;
    isCallbackInFlight.value = false;
  }
}

async function tryResumeSession(): Promise<void> {
  try {
    const session = await authApiClient.getSession();
    if (!session) return;
    isCallbackProcessing.value = true;
    await authApiClient.exchangeSession();
    window.location.assign(safeReturnTo.value);
  } catch {
    isCallbackProcessing.value = false;
  }
}

async function onContinueWithEmail(): Promise<void> {
  clearFlash();
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite um email valido.";
    return;
  }
  isEmailSubmitting.value = true;
  try {
    const result = await authApiClient.discoverEmail(email);
    if (result.accountState === "active") return void (step.value = "password");
    if (result.accountState === "pending_verification") {
      return await openVerificationStep({ email, autoSend: true, initialCooldownSeconds: result.retryAfterSeconds });
    }
    step.value = "signup";
    signupName.value = "";
    signupPassword.value = "";
  } catch (error) {
    flashError.value = resolveAuthError(error).message;
  } finally {
    isEmailSubmitting.value = false;
  }
}

async function onSubmitPassword(): Promise<void> {
  clearFlash();
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite um email valido.";
    step.value = "email";
    return;
  }
  if (!passwordValue.value) {
    flashError.value = "Digite sua senha.";
    return;
  }
  isPasswordSubmitting.value = true;
  try {
    await authApiClient.signInEmail({ email, password: passwordValue.value, callbackURL: callbackUrl.value });
    await router.replace({ name: "auth-callback", query: { returnTo: safeReturnTo.value } });
  } catch (error) {
    const resolved = resolveAuthError(error);
    flashError.value = resolved.message;
    if (resolved.code === "EMAIL_NOT_VERIFIED") await openVerificationStep({ email, autoSend: true });
  } finally {
    isPasswordSubmitting.value = false;
  }
}

async function onSubmitSignup(): Promise<void> {
  clearFlash();
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite um email valido.";
    step.value = "email";
    return;
  }
  if (!signupStrong.value) {
    flashError.value = "Use uma senha forte para criar sua conta.";
    return;
  }
  isSignupSubmitting.value = true;
  try {
    await authApiClient.signUpEmail({
      name: resolveSignupName(signupName.value, email),
      email,
      password: signupPassword.value,
      callbackURL: callbackUrl.value,
    });
    signupName.value = "";
    signupPassword.value = "";
    await openVerificationStep({ email, autoSend: false });
  } catch (error) {
    const resolved = resolveAuthError(error);
    flashError.value = resolved.message;
    if (resolved.code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL") await openVerificationStep({ email, autoSend: true });
  } finally {
    isSignupSubmitting.value = false;
  }
}

async function onSignInWithMicrosoft(): Promise<void> {
  clearFlash();
  isMicrosoftSubmitting.value = true;
  try {
    const redirectUrl = await authApiClient.startMicrosoftSignIn({
      callbackURL: callbackUrl.value,
      errorCallbackURL: callbackUrl.value,
    });
    window.location.assign(redirectUrl);
  } catch (error) {
    flashError.value = resolveAuthError(error).message;
    isMicrosoftSubmitting.value = false;
  }
}

function onBackToEmailStep(): void {
  clearFlash();
  step.value = "email";
  passwordValue.value = "";
}

async function openVerificationStep(input: {
  email: string;
  autoSend: boolean;
  initialCooldownSeconds?: number;
}): Promise<void> {
  verification.email = normalizeEmail(input.email);
  verification.error = "";
  verification.notice = "";
  verification.isSending = false;
  stopVerificationCountdown();
  step.value = "verify-pending";
  const initialCooldown = Math.max(0, input.initialCooldownSeconds ?? 0);
  if (input.autoSend) {
    if (initialCooldown > 0) {
      verification.notice = "Email de verificacao enviado recentemente.";
      startVerificationCountdown(initialCooldown);
      return;
    }
    await sendVerificationEmail({ force: true });
    return;
  }
  verification.notice = "Enviamos o email de verificacao automaticamente.";
  startVerificationCountdown(60);
}

async function sendVerificationEmail(input?: { force?: boolean }): Promise<void> {
  const force = Boolean(input?.force);
  if (!force && verification.resendSeconds > 0) return;
  if (!verification.email) return;
  verification.isSending = true;
  verification.error = "";
  try {
    await authApiClient.sendVerificationEmail({ email: verification.email, callbackURL: callbackUrl.value });
    verification.notice = "Novo email de verificacao enviado.";
    startVerificationCountdown(60);
  } catch (error) {
    verification.error = resolveAuthError(error).message;
  } finally {
    verification.isSending = false;
  }
}

async function onOpenResetPasswordStep(): Promise<void> {
  clearFlash();
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite seu email para recuperar a senha.";
    return;
  }
  step.value = "reset-code";
  resetFlow.email = email;
  resetFlow.notice = "";
  resetFlow.error = "";
  resetFlow.newPassword = "";
  resetFlow.codeDigits = ["", "", "", "", "", ""];
  await nextTick();
  focusResetCodeInput(0);
  await requestResetCode({ force: true });
}

async function requestResetCode(input?: { force?: boolean }): Promise<void> {
  const force = Boolean(input?.force);
  if (!force && resetFlow.resendSeconds > 0) return;
  if (!resetFlow.email) return;
  resetFlow.isRequesting = true;
  resetFlow.error = "";
  try {
    const result = await authApiClient.requestPasswordResetCode(resetFlow.email);
    const nextCooldown = Math.max(1, result.retryAfterSeconds || 60);
    startResetCountdown(nextCooldown);
    resetFlow.notice =
      result.status === "cooldown"
        ? "Aguarde o contador para reenviar o codigo."
        : "Codigo de verificacao enviado para seu email.";
  } catch (error) {
    resetFlow.error = resolveAuthError(error).message;
  } finally {
    resetFlow.isRequesting = false;
  }
}

async function onVerifyResetCode(): Promise<void> {
  resetFlow.error = "";
  const code = resetCode.value;
  if (!/^\d{6}$/.test(code)) {
    resetFlow.error = "Digite os 6 digitos do codigo.";
    return;
  }
  resetFlow.isVerifying = true;
  try {
    const result = await authApiClient.verifyPasswordResetCode({ email: resetFlow.email, code });
    if (!result.valid) {
      resetFlow.error = "Codigo invalido ou expirado.";
      return;
    }
    step.value = "reset-password";
    resetFlow.notice = "Codigo validado. Defina sua nova senha.";
  } catch (error) {
    resetFlow.error = resolveAuthError(error).message;
  } finally {
    resetFlow.isVerifying = false;
  }
}

async function onCompleteResetWithCode(): Promise<void> {
  resetFlow.error = "";
  if (!resetStrong.value) {
    resetFlow.error = "Use uma senha forte para continuar.";
    return;
  }
  resetFlow.isCompleting = true;
  try {
    const result = await authApiClient.completePasswordResetWithCode({
      email: resetFlow.email,
      code: resetCode.value,
      newPassword: resetFlow.newPassword,
    });
    if (!result.updated) {
      resetFlow.error = "Codigo invalido ou expirado. Solicite um novo codigo.";
      step.value = "reset-code";
      return;
    }
    resetFlow.newPassword = "";
    resetFlow.codeDigits = ["", "", "", "", "", ""];
    stopResetCountdown();
    step.value = "email";
    passwordValue.value = "";
    flashSuccess.value = "Senha atualizada com sucesso. Faca login novamente.";
  } catch (error) {
    resetFlow.error = resolveAuthError(error).message;
  } finally {
    resetFlow.isCompleting = false;
  }
}

function onBackToResetCode(): void {
  resetFlow.error = "";
  step.value = "reset-code";
}

function setResetCodeInputRef(el: Element | null, index: number): void {
  resetRefs.value[index] = el instanceof HTMLInputElement ? el : null;
}

function onResetCodeInput(index: number, event: Event): void {
  const target = event.target as HTMLInputElement;
  const value = target.value.replace(/\D/g, "").slice(-1);
  resetFlow.codeDigits[index] = value;
  if (value && index < 5) focusResetCodeInput(index + 1);
}

function onResetCodeKeydown(index: number, event: KeyboardEvent): void {
  if (event.key === "Backspace" && !resetFlow.codeDigits[index] && index > 0) focusResetCodeInput(index - 1);
  if (event.key === "ArrowLeft" && index > 0) {
    event.preventDefault();
    focusResetCodeInput(index - 1);
  }
  if (event.key === "ArrowRight" && index < 5) {
    event.preventDefault();
    focusResetCodeInput(index + 1);
  }
}

function onResetCodePaste(event: ClipboardEvent): void {
  const pasted = event.clipboardData?.getData("text") ?? "";
  const values = pasted.replace(/\D/g, "").slice(0, 6).split("");
  if (values.length === 0) return;
  event.preventDefault();
  for (let i = 0; i < 6; i += 1) resetFlow.codeDigits[i] = values[i] ?? "";
  focusResetCodeInput(Math.min(values.length, 6) - 1);
}

function focusResetCodeInput(index: number): void {
  const input = resetRefs.value[index];
  input?.focus();
  input?.select();
}

function startCountdown(seconds: number, assign: (value: number) => void, stop: () => void): ReturnType<typeof setInterval> | null {
  assign(Math.max(0, Math.floor(seconds)));
  if (seconds < 1) return null;
  return setInterval(() => {
    assign(Math.max(0, Math.floor(seconds - 1)));
    seconds -= 1;
    if (seconds <= 0) stop();
  }, 1000);
}

function startVerificationCountdown(seconds: number): void {
  stopVerificationCountdown();
  verificationTimer = startCountdown(seconds, (value) => (verification.resendSeconds = value), stopVerificationCountdown);
}

function stopVerificationCountdown(): void {
  if (verificationTimer) clearInterval(verificationTimer);
  verificationTimer = null;
}

function startResetCountdown(seconds: number): void {
  stopResetCountdown();
  resetTimer = startCountdown(seconds, (value) => (resetFlow.resendSeconds = value), stopResetCountdown);
}

function stopResetCountdown(): void {
  if (resetTimer) clearInterval(resetTimer);
  resetTimer = null;
}

function passwordRules(password: string): Rule[] {
  return [
    { key: "length", label: "Minimo de 12 caracteres", met: password.length >= 12 },
    { key: "lowercase", label: "Pelo menos 1 letra minuscula", met: /[a-z]/.test(password) },
    { key: "uppercase", label: "Pelo menos 1 letra maiuscula", met: /[A-Z]/.test(password) },
    { key: "digit", label: "Pelo menos 1 numero", met: /\d/.test(password) },
    { key: "special", label: "Pelo menos 1 caractere especial", met: /[^A-Za-z\d]/.test(password) },
  ];
}

function resolveSignupName(rawName: string, email: string): string {
  const trimmed = rawName.trim();
  if (trimmed.length > 0) return trimmed;
  const local = email.split("@")[0] ?? "";
  const normalized = local.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  if (!normalized) return "Usuario Sigfarm";
  return normalized
    .split(" ")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function applyStatusFromQuery(): void {
  const status = firstQueryValue(route.query.status);
  if (status === "email-verified") flashSuccess.value = "Email verificado com sucesso. Agora voce pode entrar.";
  if (status === "password-updated") flashSuccess.value = "Senha atualizada com sucesso. Faca login com a nova senha.";
  if (status === "signed-out") flashSuccess.value = "Sessao encerrada com sucesso.";
  if (status === "callback-error") flashError.value = "Nao foi possivel concluir o login com Microsoft. Tente novamente.";
  if (status === "session-missing") flashError.value = "Sessao de autenticacao nao encontrada. Tente novamente.";
}

function clearFlash(): void {
  flashError.value = null;
  flashSuccess.value = null;
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function firstQueryValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}

function withOptionalReferrer(input: {
  returnTo: string | undefined;
  appBaseUrl: string;
  defaultReturnTo: string;
  allowedOrigins: string[];
}): {
  returnTo: string | undefined;
  appBaseUrl: string;
  defaultReturnTo: string;
  allowedOrigins: string[];
  referrer?: string;
} {
  if (typeof document === "undefined") return input;
  const referrer = document.referrer?.trim();
  if (!referrer) return input;
  return { ...input, referrer };
}

function readAuthErrorCode(details: unknown): string | null {
  if (!details || typeof details !== "object") return null;
  const directCode = (details as { code?: unknown }).code;
  if (typeof directCode === "string") return directCode;
  const nestedCode = (details as { error?: { code?: unknown } }).error?.code;
  if (typeof nestedCode === "string") return nestedCode;
  return null;
}

function resolveAuthError(error: unknown): { message: string; code: string | null } {
  if (error instanceof AuthApiError) {
    const code = readAuthErrorCode(error.details);
    if (code === "EMAIL_NOT_VERIFIED") return { code, message: "Email nao verificado." };
    if (code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL") {
      return { code, message: "Este email ja possui cadastro. Tente entrar ou recuperar a senha." };
    }
    if (error.status === 429) return { code, message: "Muitas tentativas. Aguarde alguns segundos e tente novamente." };
    if (error.status === 401 || error.status === 422) return { code, message: error.message || "Dados invalidos." };
    return { code, message: error.message || "Falha na autenticacao." };
  }
  if (error instanceof Error && error.message) return { code: null, message: error.message };
  return { code: null, message: "Falha na autenticacao." };
}
</script>

<template>
  <article class="login-view panel-screen">
    <header class="brand-hero" aria-label="Sigfarm Intelligence">
      <div class="brand-logo-large-frame">
        <img src="/sigfarm-logo.png" alt="Sigfarm Intelligence" class="brand-logo-large" />
      </div>
      <p class="brand-company">Sigfarm Intelligence</p>
    </header>

    <section class="login-content-zone">
      <div class="feedback-slot" aria-live="polite" aria-atomic="true">
        <Transition name="fade-up" mode="out-in">
          <p
            v-if="globalFeedback"
            :key="globalFeedback.message"
            class="flash"
            :class="globalFeedback.type === 'error' ? 'flash-error' : 'flash-success'"
          >
            {{ globalFeedback.message }}
          </p>
          <span v-else key="global-feedback-empty" class="feedback-empty" aria-hidden="true" />
        </Transition>
      </div>

      <Transition name="step-slide" mode="out-in">
        <section v-if="step === 'email'" key="email" class="step-block">
          <h1>Entrar</h1>
          <p class="step-caption">Digite seu email para continuar.</p>
          <form class="form-grid" @submit.prevent="onContinueWithEmail">
            <label>Email
              <input
                v-model.trim="emailValue"
                type="email"
                autocomplete="username email"
                placeholder="nome@empresa.com"
                required
              />
            </label>
            <button class="btn-primary" :class="{ 'is-loading': isEmailSubmitting }" type="submit" :disabled="isEmailSubmitting">
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label">Continuar</span>
            </button>
          </form>
          <div class="helper-row">
            <button class="link-like" type="button" @click="onOpenResetPasswordStep">Esqueceu sua senha?</button>
          </div>
        </section>

        <section v-else-if="step === 'password'" key="password" class="step-block">
          <h1>Entrar com senha</h1>
          <p class="step-caption">{{ normalizedEmail }}</p>
          <form class="form-grid" @submit.prevent="onSubmitPassword">
            <label>Senha
              <div class="input-with-toggle">
                <input v-model="passwordValue" :type="showPasswordField ? 'text' : 'password'" autocomplete="current-password" placeholder="Digite sua senha" class="has-toggle" required />
                <button class="password-toggle" type="button" :aria-label="showPasswordField ? 'Ocultar senha' : 'Mostrar senha'" @click="showPasswordField = !showPasswordField">
                  <svg v-if="showPasswordField" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M4 4 20 20" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                    <path d="M10.55 10.55a2 2 0 0 0 2.9 2.9" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                    <path d="M6.7 6.7A12.4 12.4 0 0 0 3 12s3.3 6 9 6c2.1 0 3.9-.8 5.4-1.9" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                    <path d="M14.7 5.2A9.9 9.9 0 0 1 21 12c-.6 1.1-1.4 2.4-2.6 3.6" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M2.4 12s3.5-6 9.6-6 9.6 6 9.6 6-3.5 6-9.6 6-9.6-6-9.6-6Z" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round" />
                    <circle cx="12" cy="12" r="2.8" stroke="currentColor" stroke-width="1.9" />
                  </svg>
                </button>
              </div>
            </label>
            <button class="btn-primary" :class="{ 'is-loading': isPasswordSubmitting }" type="submit" :disabled="isPasswordSubmitting">
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label">Entrar</span>
            </button>
          </form>
          <div class="helper-row">
            <button class="link-like" type="button" @click="onOpenResetPasswordStep">Esqueceu sua senha?</button>
            <button class="link-like" type="button" @click="onBackToEmailStep">Trocar email</button>
          </div>
        </section>

        <section v-else-if="step === 'signup'" key="signup" class="step-block">
          <h1>Criar conta</h1>
          <p class="step-caption">{{ normalizedEmail }}</p>
          <form class="form-grid" @submit.prevent="onSubmitSignup">
            <label>Nome (opcional)
              <input v-model.trim="signupName" type="text" autocomplete="name" placeholder="Como voce prefere ser chamado" />
            </label>
            <label>Senha
              <div class="input-with-toggle">
                <input v-model="signupPassword" :type="showSignupPasswordField ? 'text' : 'password'" autocomplete="new-password" placeholder="Crie uma senha forte" class="has-toggle" required />
                <button class="password-toggle" type="button" :aria-label="showSignupPasswordField ? 'Ocultar senha' : 'Mostrar senha'" @click="showSignupPasswordField = !showSignupPasswordField">
                  <svg v-if="showSignupPasswordField" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M4 4 20 20" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                    <path d="M10.55 10.55a2 2 0 0 0 2.9 2.9" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                    <path d="M6.7 6.7A12.4 12.4 0 0 0 3 12s3.3 6 9 6c2.1 0 3.9-.8 5.4-1.9" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                    <path d="M14.7 5.2A9.9 9.9 0 0 1 21 12c-.6 1.1-1.4 2.4-2.6 3.6" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M2.4 12s3.5-6 9.6-6 9.6 6 9.6 6-3.5 6-9.6 6-9.6-6-9.6-6Z" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round" />
                    <circle cx="12" cy="12" r="2.8" stroke="currentColor" stroke-width="1.9" />
                  </svg>
                </button>
              </div>
            </label>
            <div class="password-checklist-slot" :class="{ visible: showSignupChecklist }" aria-live="polite">
              <TransitionGroup v-if="showSignupChecklist" name="check-item" tag="ul" class="password-checklist signup-checklist">
                <li v-for="(rule, index) in signupRules" :key="`signup-${rule.key}`" class="password-rule" :class="rule.met ? 'met' : 'unmet'" :style="{ '--stagger-delay': `${index * 55}ms` }">
                  <span class="rule-icon" aria-hidden="true">
                    <svg v-if="rule.met" viewBox="0 0 16 16" fill="none">
                      <path d="M3.5 8.4 6.5 11.2 12.5 4.8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                    <svg v-else viewBox="0 0 16 16" fill="none">
                      <path d="m5 5 6 6m0-6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
                    </svg>
                  </span>
                  <span class="rule-text">{{ rule.label }}</span>
                </li>
              </TransitionGroup>
            </div>
            <button class="btn-primary" :class="{ 'is-loading': isSignupSubmitting }" type="submit" :disabled="isSignupSubmitting || !signupStrong">
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label">Criar conta</span>
            </button>
          </form>
          <div class="helper-row">
            <button class="link-like" type="button" @click="onBackToEmailStep">Voltar</button>
          </div>
        </section>

        <section v-else-if="step === 'verify-pending'" key="verify" class="step-block">
          <h1>Verifique seu email</h1>
          <p class="step-caption">{{ verification.email }}</p>
          <div class="state-card">
            <div class="state-icon success-envelope" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <rect x="3" y="5" width="18" height="14" rx="3" stroke="currentColor" stroke-width="1.8" />
                <path d="M4 7.4 12 13l8-5.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </div>
            <p class="state-text">Abra o link enviado no seu email para ativar o acesso.</p>
          </div>
          <div class="feedback-slot step-feedback" aria-live="polite" aria-atomic="true">
            <Transition name="fade-up" mode="out-in">
              <p v-if="verificationFeedback" :key="verificationFeedback.message" class="flash" :class="verificationFeedback.type === 'error' ? 'flash-error' : 'flash-success'">
                {{ verificationFeedback.message }}
              </p>
              <span v-else key="verify-feedback-empty" class="feedback-empty" aria-hidden="true" />
            </Transition>
          </div>
          <div class="form-grid">
            <button class="btn-primary" :class="{ 'is-loading': verification.isSending }" type="button" :disabled="verification.isSending || verification.resendSeconds > 0" @click="sendVerificationEmail()">
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label">{{ verification.resendSeconds > 0 ? `Reenviar em ${verification.resendSeconds}s` : "Reenviar email" }}</span>
            </button>
            <button class="btn-ghost" type="button" @click="onBackToEmailStep">Voltar ao login</button>
          </div>
        </section>

        <section v-else-if="step === 'reset-code'" key="reset-code" class="step-block">
          <h1>Recuperar senha</h1>
          <p class="step-caption">{{ resetFlow.email }}</p>
          <div class="state-card">
            <div class="state-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <rect x="4" y="10" width="16" height="10" rx="2.6" stroke="currentColor" stroke-width="1.8" />
                <path d="M8 10V8a4 4 0 0 1 8 0v2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
              </svg>
            </div>
            <p class="state-text">Digite o codigo de 6 digitos enviado para seu email.</p>
          </div>
          <div class="otp-grid" @paste="onResetCodePaste">
            <input v-for="(_, index) in resetFlow.codeDigits" :key="`otp-${index}`" :ref="(el) => setResetCodeInputRef(el as Element | null, index)" :value="resetFlow.codeDigits[index]" inputmode="numeric" maxlength="1" autocomplete="one-time-code" class="otp-input" @input="onResetCodeInput(index, $event)" @keydown="onResetCodeKeydown(index, $event)" />
          </div>
          <div class="feedback-slot step-feedback" aria-live="polite" aria-atomic="true">
            <Transition name="fade-up" mode="out-in">
              <p v-if="resetFeedback" :key="resetFeedback.message" class="flash" :class="resetFeedback.type === 'error' ? 'flash-error' : 'flash-success'">{{ resetFeedback.message }}</p>
              <span v-else key="reset-feedback-empty" class="feedback-empty" aria-hidden="true" />
            </Transition>
          </div>
          <div class="form-grid">
            <button class="btn-primary" :class="{ 'is-loading': resetFlow.isVerifying }" type="button" :disabled="resetFlow.isVerifying" @click="onVerifyResetCode"><span class="btn-spinner" aria-hidden="true" /><span class="btn-label">Validar codigo</span></button>
            <button class="btn-ghost" :class="{ 'is-loading': resetFlow.isRequesting }" type="button" :disabled="resetFlow.isRequesting || resetFlow.resendSeconds > 0" @click="requestResetCode()"><span class="btn-spinner" aria-hidden="true" /><span class="btn-label">{{ resetFlow.resendSeconds > 0 ? `Reenviar em ${resetFlow.resendSeconds}s` : "Reenviar codigo" }}</span></button>
            <button class="link-like" type="button" @click="onBackToEmailStep">Voltar ao login</button>
          </div>
        </section>

        <section v-else key="reset-password" class="step-block">
          <h1>Nova senha</h1>
          <p class="step-caption">{{ resetFlow.email }}</p>
          <form class="form-grid" @submit.prevent="onCompleteResetWithCode">
            <label>Nova senha
              <div class="input-with-toggle">
                <input v-model="resetFlow.newPassword" :type="showResetPasswordField ? 'text' : 'password'" autocomplete="new-password" placeholder="Digite uma senha forte" class="has-toggle" required />
                <button class="password-toggle" type="button" :aria-label="showResetPasswordField ? 'Ocultar senha' : 'Mostrar senha'" @click="showResetPasswordField = !showResetPasswordField">
                  <svg v-if="showResetPasswordField" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M4 4 20 20" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                    <path d="M10.55 10.55a2 2 0 0 0 2.9 2.9" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                    <path d="M6.7 6.7A12.4 12.4 0 0 0 3 12s3.3 6 9 6c2.1 0 3.9-.8 5.4-1.9" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                    <path d="M14.7 5.2A9.9 9.9 0 0 1 21 12c-.6 1.1-1.4 2.4-2.6 3.6" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M2.4 12s3.5-6 9.6-6 9.6 6 9.6 6-3.5 6-9.6 6-9.6-6-9.6-6Z" stroke="currentColor" stroke-width="1.9" stroke-linejoin="round" />
                    <circle cx="12" cy="12" r="2.8" stroke="currentColor" stroke-width="1.9" />
                  </svg>
                </button>
              </div>
            </label>
            <div class="password-checklist-slot" :class="{ visible: showResetChecklist }" aria-live="polite">
              <TransitionGroup v-if="showResetChecklist" name="check-item" tag="ul" class="password-checklist signup-checklist">
                <li v-for="(rule, index) in resetRules" :key="`reset-${rule.key}`" class="password-rule" :class="rule.met ? 'met' : 'unmet'" :style="{ '--stagger-delay': `${index * 55}ms` }">
                  <span class="rule-icon" aria-hidden="true">
                    <svg v-if="rule.met" viewBox="0 0 16 16" fill="none">
                      <path d="M3.5 8.4 6.5 11.2 12.5 4.8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                    <svg v-else viewBox="0 0 16 16" fill="none">
                      <path d="m5 5 6 6m0-6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
                    </svg>
                  </span>
                  <span class="rule-text">{{ rule.label }}</span>
                </li>
              </TransitionGroup>
            </div>
            <div class="feedback-slot step-feedback" aria-live="polite" aria-atomic="true">
              <Transition name="fade-up" mode="out-in">
                <p v-if="resetFlow.error" key="reset-password-error" class="flash flash-error">{{ resetFlow.error }}</p>
                <span v-else key="reset-password-empty" class="feedback-empty" aria-hidden="true" />
              </Transition>
            </div>
            <button class="btn-primary" :class="{ 'is-loading': resetFlow.isCompleting }" type="submit" :disabled="resetFlow.isCompleting || !resetStrong"><span class="btn-spinner" aria-hidden="true" /><span class="btn-label">Atualizar senha</span></button>
            <button class="btn-ghost" type="button" @click="onBackToResetCode">Voltar para codigo</button>
          </form>
        </section>
      </Transition>

      <div v-if="shouldShowSocial" class="auth-social-area">
        <div class="section-divider" />
        <button class="btn-microsoft" :class="{ 'is-loading': isMicrosoftSubmitting }" type="button" :disabled="isMicrosoftSubmitting" @click="onSignInWithMicrosoft">
          <span class="btn-spinner" aria-hidden="true" />
          <span class="microsoft-icon" aria-hidden="true">
            <span class="microsoft-tile red" />
            <span class="microsoft-tile green" />
            <span class="microsoft-tile blue" />
            <span class="microsoft-tile yellow" />
          </span>
          <span class="btn-label">Entrar com Microsoft</span>
        </button>
      </div>
    </section>

    <Transition name="fade-up">
      <div v-if="isCallbackProcessing" class="callback-overlay" aria-live="polite" aria-busy="true">
        <div class="callback-loader">
          <span class="ring-loader" />
        </div>
      </div>
    </Transition>
  </article>
</template>
