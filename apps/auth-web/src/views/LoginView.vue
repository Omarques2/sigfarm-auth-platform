<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import AuthBackButton from "../components/AuthBackButton.vue";
import { authWebEnv } from "../config/env";
import { authApiClient, AuthApiError } from "../lib/auth-api";
import {
  getResetProgressLabel,
  getResetRequestCountdownSeconds,
  getResetRequestNotice,
  getResetResendHint,
  getResendLabel,
} from "../lib/reset-flow";
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
const signupConfirmPassword = ref("");
const emailTouched = ref(false);
const showPasswordField = ref(false);
const showSignupPasswordField = ref(false);
const showSignupConfirmPasswordField = ref(false);
const showResetPasswordField = ref(false);
const showResetConfirmPasswordField = ref(false);
const isSignupPasswordFocused = ref(false);
const isResetPasswordFocused = ref(false);

const isEmailSubmitting = ref(false);
const isPasswordSubmitting = ref(false);
const isSignupSubmitting = ref(false);
const isMicrosoftSubmitting = ref(false);
const isGoogleSubmitting = ref(false);

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
  confirmPassword: "",
});

let verificationTimer: ReturnType<typeof setInterval> | null = null;
let resetTimer: ReturnType<typeof setInterval> | null = null;
let resetAutoVerifyTimer: ReturnType<typeof setTimeout> | null = null;
const resetRefs = ref<Array<HTMLInputElement | null>>([]);
const emailInputRef = ref<HTMLInputElement | null>(null);
const passwordInputRef = ref<HTMLInputElement | null>(null);
const signupPasswordInputRef = ref<HTMLInputElement | null>(null);
const signupEmailInputRef = ref<HTMLInputElement | null>(null);
const resetPasswordInputRef = ref<HTMLInputElement | null>(null);

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
const showSignupChecklist = computed(() => isSignupPasswordFocused.value);
const resetRules = computed(() => passwordRules(resetFlow.newPassword));
const resetStrong = computed(() => resetRules.value.every((rule) => rule.met));
const showResetChecklist = computed(() => isResetPasswordFocused.value);
const signupPasswordsMatch = computed(
  () =>
    signupPassword.value.length > 0 &&
    signupConfirmPassword.value.length > 0 &&
    signupPassword.value === signupConfirmPassword.value,
);
const resetPasswordsMatch = computed(
  () =>
    resetFlow.newPassword.length > 0 &&
    resetFlow.confirmPassword.length > 0 &&
    resetFlow.newPassword === resetFlow.confirmPassword,
);
const isEmailValid = computed(() => isValidEmail(normalizedEmail.value));
const emailValidationMessage = computed(() => {
  if (!emailTouched.value) return "";
  if (!normalizedEmail.value) return "Digite seu e-mail.";
  if (!isValidEmail(normalizedEmail.value)) return "Formato inválido. Exemplo: nome@empresa.com";
  return "E-mail válido.";
});
const emailValidationTone = computed<"neutral" | "error" | "success">(() => {
  if (!emailTouched.value || !emailValidationMessage.value) return "neutral";
  return isValidEmail(normalizedEmail.value) ? "success" : "error";
});
const resetProgressLabel = computed(() =>
  getResetProgressLabel(step.value === "reset-password" ? "reset-password" : "reset-code"),
);
const verificationResendLabel = computed(() => getResendLabel("email", verification.resendSeconds));
const resetResendLabel = computed(() => getResendLabel("codigo", resetFlow.resendSeconds));
const resetResendHint = computed(() => getResetResendHint());
const maskedResetEmail = computed(() => maskEmail(resetFlow.email));
const shouldShowSocial = computed(
  () => (step.value === "email" || step.value === "password") && !isCallbackProcessing.value,
);
const shouldShowStepBack = computed(() =>
  step.value === "password" ||
  step.value === "signup" ||
  step.value === "verify-pending" ||
  step.value === "reset-code" ||
  step.value === "reset-password",
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
  resetFlow.error ? { type: "error" as const, message: resetFlow.error } : null,
);
const resetCompromisedPasswordMessage = computed(() =>
  resetFlow.error === "Essa senha já apareceu em vazamentos conhecidos. Escolha outra."
    ? resetFlow.error
    : "",
);

onMounted(async () => {
  applyStatusFromQuery();
  await maybeHandleCallback();
  if (!isCallbackRoute()) await tryResumeSession();
  await nextTick();
  emailInputRef.value?.focus();
});
watch(
  () => route.fullPath,
  async () => {
    applyStatusFromQuery();
    await maybeHandleCallback();
  },
);
watch(step, async (nextStep) => {
  await nextTick();
  if (nextStep === "email") emailInputRef.value?.focus();
  if (nextStep === "password") passwordInputRef.value?.focus();
  if (nextStep === "signup") {
    if (!normalizedEmail.value) signupEmailInputRef.value?.focus();
    else signupPasswordInputRef.value?.focus();
  }
  if (nextStep === "reset-code") focusResetCodeInput(0);
  if (nextStep === "reset-password") resetPasswordInputRef.value?.focus();
});
watch(resetCode, (value) => {
  if (step.value !== "reset-code") return;
  if (!/^\d{6}$/.test(value) || resetFlow.isVerifying) return;
  if (resetAutoVerifyTimer) clearTimeout(resetAutoVerifyTimer);
  resetAutoVerifyTimer = setTimeout(() => {
    void onVerifyResetCode();
  }, 180);
});
onBeforeUnmount(() => {
  stopVerificationCountdown();
  stopResetCountdown();
  if (resetAutoVerifyTimer) clearTimeout(resetAutoVerifyTimer);
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
      flashError.value = "Não foi possível concluir o login social. Tente novamente.";
      await router.replace({ name: "login", query: { status: "callback-error", returnTo: safeReturnTo.value } });
      return;
    }
    const session = await authApiClient.getSession();
    if (!session) {
      flashError.value = "Sessão de autenticação não encontrada. Tente novamente.";
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
  emailTouched.value = true;
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite um e-mail válido.";
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
  emailTouched.value = true;
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite um e-mail válido.";
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
  emailTouched.value = true;
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite um e-mail válido.";
    step.value = "email";
    return;
  }
  if (!signupStrong.value) {
    flashError.value = "Use uma senha com no mínimo 12 caracteres.";
    return;
  }
  if (!signupPasswordsMatch.value) {
    flashError.value = "As senhas informadas não coincidem.";
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
    signupConfirmPassword.value = "";
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

async function onSignInWithGoogle(): Promise<void> {
  clearFlash();
  isGoogleSubmitting.value = true;
  try {
    const redirectUrl = await authApiClient.startGoogleSignIn({
      callbackURL: callbackUrl.value,
      errorCallbackURL: callbackUrl.value,
    });
    window.location.assign(redirectUrl);
  } catch (error) {
    flashError.value = resolveAuthError(error).message;
    isGoogleSubmitting.value = false;
  }
}

function onBackToEmailStep(): void {
  clearFlash();
  stopVerificationCountdown();
  stopResetCountdown();
  if (resetAutoVerifyTimer) {
    clearTimeout(resetAutoVerifyTimer);
    resetAutoVerifyTimer = null;
  }
  step.value = "email";
  passwordValue.value = "";
  signupConfirmPassword.value = "";
  resetFlow.confirmPassword = "";
}

function onOpenSignupStep(): void {
  clearFlash();
  signupConfirmPassword.value = "";
  step.value = "signup";
}

function onBackFromCurrentStep(): void {
  if (step.value === "reset-password") {
    onBackToLoginFromResetPassword();
    return;
  }
  onBackToEmailStep();
}

function onBackToLoginFromResetPassword(): void {
  clearFlash();
  stopResetCountdown();
  resetFlow.error = "";
  resetFlow.newPassword = "";
  resetFlow.confirmPassword = "";
  resetFlow.codeDigits = ["", "", "", "", "", ""];
  step.value = "email";
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
      verification.notice = "E-mail de verificação enviado recentemente.";
      startVerificationCountdown(initialCooldown);
      return;
    }
    await sendVerificationEmail({ force: true });
    return;
  }
  verification.notice = "Enviamos o e-mail de verificação automaticamente.";
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
    verification.notice = "Novo e-mail de verificação enviado.";
    startVerificationCountdown(60);
  } catch (error) {
    verification.error = resolveAuthError(error).message;
  } finally {
    verification.isSending = false;
  }
}

async function onOpenResetPasswordStep(): Promise<void> {
  clearFlash();
  emailTouched.value = true;
  const email = normalizedEmail.value;
  if (!isValidEmail(email)) {
    flashError.value = "Digite seu e-mail para recuperar a senha.";
    return;
  }
  step.value = "reset-code";
  resetFlow.email = email;
  // Show a generic message immediately to avoid timing hints in UI.
  resetFlow.notice = getResetRequestNotice("sent");
  resetFlow.error = "";
  resetFlow.newPassword = "";
  resetFlow.confirmPassword = "";
  resetFlow.codeDigits = ["", "", "", "", "", ""];
  startResetCountdown(getResetRequestCountdownSeconds(0));
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
  // Keep notice stable while request is in-flight.
  resetFlow.notice = getResetRequestNotice("sent");
  if (resetFlow.resendSeconds < 1) {
    startResetCountdown(getResetRequestCountdownSeconds(0));
  }
  try {
    const result = await authApiClient.requestPasswordResetCode(resetFlow.email);
    resetFlow.notice = getResetRequestNotice(result.status);
  } catch (error) {
    resetFlow.error = resolveAuthError(error).message;
  } finally {
    resetFlow.isRequesting = false;
  }
}

async function onVerifyResetCode(): Promise<void> {
  resetFlow.error = "";
  if (resetAutoVerifyTimer) {
    clearTimeout(resetAutoVerifyTimer);
    resetAutoVerifyTimer = null;
  }
  const code = resetCode.value;
  if (!/^\d{6}$/.test(code)) {
    resetFlow.error = "Digite os 6 dígitos do código.";
    return;
  }
  resetFlow.isVerifying = true;
  try {
    const result = await authApiClient.verifyPasswordResetCode({ email: resetFlow.email, code });
    if (!result.valid) {
      resetFlow.error = "Código inválido ou expirado.";
      return;
    }
    step.value = "reset-password";
    resetFlow.notice = "Código validado. Defina sua nova senha.";
  } catch (error) {
    resetFlow.error = resolveAuthError(error).message;
  } finally {
    resetFlow.isVerifying = false;
  }
}

async function onCompleteResetWithCode(): Promise<void> {
  resetFlow.error = "";
  if (!resetStrong.value) {
    resetFlow.error = "Use uma senha com no mínimo 12 caracteres.";
    return;
  }
  if (!resetPasswordsMatch.value) {
    resetFlow.error = "As senhas informadas não coincidem.";
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
      resetFlow.error = "Código inválido ou expirado. Solicite um novo código.";
      step.value = "reset-code";
      return;
    }
    resetFlow.newPassword = "";
    resetFlow.confirmPassword = "";
    resetFlow.codeDigits = ["", "", "", "", "", ""];
    stopResetCountdown();
    step.value = "email";
    passwordValue.value = "";
    flashSuccess.value = "Senha atualizada com sucesso. Faça login novamente.";
  } catch (error) {
    resetFlow.error = resolveAuthError(error).message;
  } finally {
    resetFlow.isCompleting = false;
  }
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
    { key: "length", label: "Mínimo de 12 caracteres", met: password.length >= 12 },
  ];
}

function resolveSignupName(rawName: string, email: string): string {
  const trimmed = rawName.trim();
  if (trimmed.length > 0) return trimmed;
  const local = email.split("@")[0] ?? "";
  const normalized = local.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  if (!normalized) return "Usuário Sigfarm";
  return normalized
    .split(" ")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function maskEmail(email: string): string {
  const normalized = normalizeEmail(email);
  const [local = "", domain = ""] = normalized.split("@");
  if (!local || !domain) return email;
  const localMasked = `${local.slice(0, Math.min(3, local.length))}***`;
  const domainParts = domain.split(".");
  const host = domainParts[0] ?? "";
  const tld = domainParts.slice(1).join(".");
  const hostMasked = `${host.slice(0, Math.min(3, host.length))}***`;
  return `${localMasked}@${hostMasked}${tld ? `.${tld}` : ""}`;
}

function applyStatusFromQuery(): void {
  const status = firstQueryValue(route.query.status);
  if (status === "email-verified") flashSuccess.value = "E-mail verificado com sucesso. Agora você pode entrar.";
  if (status === "password-updated") flashSuccess.value = "Senha atualizada com sucesso. Faça login com a nova senha.";
  if (status === "signed-out") flashSuccess.value = "Sessão encerrada com sucesso.";
  if (status === "callback-error") flashError.value = "Não foi possível concluir o login social. Tente novamente.";
  if (status === "session-missing") flashError.value = "Sessão de autenticação não encontrada. Tente novamente.";
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
    if (code === "EMAIL_NOT_VERIFIED") return { code, message: "E-mail não verificado." };
    if (code === "PASSWORD_POLICY_VIOLATION") {
      return { code, message: "Use uma senha com no mínimo 12 caracteres." };
    }
    if (code === "PASSWORD_COMPROMISED") {
      return { code, message: "Essa senha já apareceu em vazamentos conhecidos. Escolha outra." };
    }
    if (error.status === 422 && code === "INVALID_CREDENTIALS" && error.message) {
      return { code, message: error.message };
    }
    if (code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL") {
      return { code, message: "Não foi possível concluir com esse e-mail. Tente entrar ou recuperar senha." };
    }
    if (error.status === 429) return { code, message: "Muitas tentativas. Aguarde alguns segundos e tente novamente." };
    if (error.status === 401) {
      return { code, message: "E-mail ou senha inválidos." };
    }
    return { code, message: "Não foi possível concluir a solicitação. Tente novamente." };
  }
  if (error instanceof Error && error.message) return { code: null, message: error.message };
  return { code: null, message: "Falha na autenticação." };
}
</script>

<template>
  <article class="login-view panel-screen">
    <div class="login-layout">
      <section class="login-main-surface">
        <AuthBackButton v-if="shouldShowStepBack" @click="onBackFromCurrentStep" />
        <header class="brand-hero" :class="{ compact: step !== 'email' }" aria-label="Sigfarm Intelligence">
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

      <div class="step-stage">
      <Transition name="step-slide">
        <section v-if="step === 'email'" key="email" class="step-block">
          <h1 class="title-with-icon">
            <span class="title-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <path d="M12.5 4.5h5.3a1.7 1.7 0 0 1 1.7 1.7v11.6a1.7 1.7 0 0 1-1.7 1.7h-5.3" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M4.5 12h11" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                <path d="m12.1 8.8 3.2 3.2-3.2 3.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </span>
            <span>Entrar</span>
          </h1>
          <p class="step-caption">Informe seu e-mail para continuar.</p>
          <form class="form-grid" @submit.prevent="onContinueWithEmail">
            <label for="login-email">E-mail</label>
            <input
              id="login-email"
              ref="emailInputRef"
              v-model.trim="emailValue"
              type="email"
              autocomplete="username email"
              placeholder="nome@provedor.com"
              :aria-describedby="'login-email-helper'"
              required
              @input="emailTouched = true"
            />
            <div id="login-email-helper" class="inline-helper-slot" aria-live="polite">
              <span
                v-if="emailValidationMessage"
                class="inline-hint"
                :class="{
                  'hint-error': emailValidationTone === 'error',
                  'hint-success': emailValidationTone === 'success',
                }"
              >
                {{ emailValidationMessage }}
              </span>
              <span v-else class="feedback-empty" aria-hidden="true" />
            </div>
            <button class="btn-primary" :class="{ 'is-loading': isEmailSubmitting }" type="submit" :disabled="isEmailSubmitting || !isEmailValid">
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label">Continuar</span>
            </button>
          </form>
          <div class="helper-row single">
            <button class="link-like" type="button" @click="onOpenSignupStep">Criar conta</button>
          </div>
        </section>

        <section v-else-if="step === 'password'" key="password" class="step-block">
          <h1>Digite sua senha</h1>
          <p class="step-caption">{{ normalizedEmail }}</p>
          <button class="link-like step-inline-link" type="button" @click="onBackToEmailStep">Não é você? Trocar e-mail</button>
          <form class="form-grid" @submit.prevent="onSubmitPassword">
            <label for="login-password">Senha</label>
            <div class="input-with-toggle">
                <input id="login-password" ref="passwordInputRef" v-model="passwordValue" :type="showPasswordField ? 'text' : 'password'" autocomplete="current-password" placeholder="Digite sua senha" class="has-toggle" required />
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
            <button class="btn-primary" :class="{ 'is-loading': isPasswordSubmitting }" type="submit" :disabled="isPasswordSubmitting">
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label btn-label-with-icon">
                <svg class="btn-action-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M12.5 4.5h5.3a1.7 1.7 0 0 1 1.7 1.7v11.6a1.7 1.7 0 0 1-1.7 1.7h-5.3" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                  <path d="M4.5 12h11" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                  <path d="m12.1 8.8 3.2 3.2-3.2 3.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
                <span>Entrar</span>
              </span>
            </button>
          </form>
          <div class="helper-row">
            <button class="link-like" type="button" @click="onOpenResetPasswordStep">Esqueceu sua senha?</button>
          </div>
        </section>

        <section v-else-if="step === 'signup'" key="signup" class="step-block">
          <h1 class="title-with-icon">
            <span class="title-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <circle cx="9" cy="8" r="3.2" stroke="currentColor" stroke-width="1.9" />
                <path d="M3.8 18.2c.8-2.6 2.9-4.2 5.2-4.2s4.4 1.6 5.2 4.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                <path d="M18 9.2v6.2M14.9 12.3h6.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
              </svg>
            </span>
            <span>Criar conta</span>
          </h1>
          <p class="step-caption">
            {{ normalizedEmail ? normalizedEmail : "Informe seus dados para criar o acesso." }}
          </p>
          <form class="form-grid" @submit.prevent="onSubmitSignup">
            <label for="signup-email">E-mail</label>
            <input
              id="signup-email"
              ref="signupEmailInputRef"
              v-model.trim="emailValue"
              type="email"
              autocomplete="username email"
              placeholder="nome@provedor.com"
              required
              @input="emailTouched = true"
            />
            <label for="signup-name">Nome (opcional)</label>
            <input id="signup-name" v-model.trim="signupName" type="text" autocomplete="name" placeholder="Como você prefere ser chamado" />
            <label for="signup-password">Senha</label>
              <div class="input-with-toggle">
                <input id="signup-password" ref="signupPasswordInputRef" v-model="signupPassword" :type="showSignupPasswordField ? 'text' : 'password'" autocomplete="new-password" placeholder="Crie uma senha forte" class="has-toggle" required @focus="isSignupPasswordFocused = true" @blur="isSignupPasswordFocused = false" />
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
            <label for="signup-confirm-password">Confirmar senha</label>
            <div class="input-with-toggle">
              <input id="signup-confirm-password" v-model="signupConfirmPassword" :type="showSignupConfirmPasswordField ? 'text' : 'password'" autocomplete="new-password" placeholder="Repita a senha" class="has-toggle" required />
              <button class="password-toggle" type="button" :aria-label="showSignupConfirmPasswordField ? 'Ocultar senha' : 'Mostrar senha'" @click="showSignupConfirmPasswordField = !showSignupConfirmPasswordField">
                <svg v-if="showSignupConfirmPasswordField" viewBox="0 0 24 24" fill="none" aria-hidden="true">
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
            <button class="btn-primary" :class="{ 'is-loading': isSignupSubmitting }" type="submit" :disabled="isSignupSubmitting || !signupStrong || !signupPasswordsMatch">
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label btn-label-with-icon">
                <svg class="btn-action-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <circle cx="9" cy="8" r="3.2" stroke="currentColor" stroke-width="1.9" />
                  <path d="M3.8 18.2c.8-2.6 2.9-4.2 5.2-4.2s4.4 1.6 5.2 4.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                  <path d="M18 9.2v6.2M14.9 12.3h6.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" />
                </svg>
                <span>Criar conta</span>
              </span>
            </button>
          </form>
        </section>

        <section v-else-if="step === 'verify-pending'" key="verify" class="step-block">
          <h1>Verifique seu e-mail</h1>
          <p class="step-caption">{{ verification.email }}</p>
          <div class="state-card">
            <div class="state-icon success-envelope" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <rect x="3" y="5" width="18" height="14" rx="3" stroke="currentColor" stroke-width="1.8" />
                <path d="M4 7.4 12 13l8-5.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </div>
            <p class="state-text">Abra o link enviado no seu e-mail para ativar o acesso.</p>
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
              <span class="btn-label">{{ verificationResendLabel }}</span>
            </button>
          </div>
        </section>

        <section v-else-if="step === 'reset-code'" key="reset-code" class="step-block">
          <p class="step-progress">{{ resetProgressLabel }}</p>
          <h1>Recuperar senha</h1>
          <p class="step-caption">{{ maskedResetEmail }}</p>
          <button class="link-like step-inline-link" type="button" @click="onBackToEmailStep">Não é você? Trocar e-mail</button>
          <div class="state-card">
            <div class="state-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <rect x="4" y="10" width="16" height="10" rx="2.6" stroke="currentColor" stroke-width="1.8" />
                <path d="M8 10V8a4 4 0 0 1 8 0v2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
              </svg>
            </div>
            <p class="state-text">Enviamos um código de 6 dígitos para {{ maskedResetEmail }}.</p>
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
          <p class="inline-hint hint-neutral">{{ resetResendHint }}</p>
          <div class="form-grid">
            <button class="btn-primary" :class="{ 'is-loading': resetFlow.isVerifying }" type="button" :disabled="resetFlow.isVerifying" @click="onVerifyResetCode"><span class="btn-spinner" aria-hidden="true" /><span class="btn-label">Validar código</span></button>
            <button class="btn-ghost" :class="{ 'is-loading': resetFlow.isRequesting }" type="button" :disabled="resetFlow.isRequesting || resetFlow.resendSeconds > 0" @click="requestResetCode()"><span class="btn-spinner" aria-hidden="true" /><span class="btn-label">{{ resetResendLabel }}</span></button>
          </div>
        </section>

        <section v-else key="reset-password" class="step-block">
          <p class="step-progress">{{ resetProgressLabel }}</p>
          <h1>Nova senha</h1>
          <p class="step-caption">{{ maskedResetEmail }}</p>
          <form class="form-grid" @submit.prevent="onCompleteResetWithCode">
            <label for="reset-password">Nova senha</label>
              <div class="input-with-toggle">
                <input id="reset-password" ref="resetPasswordInputRef" v-model="resetFlow.newPassword" :type="showResetPasswordField ? 'text' : 'password'" autocomplete="new-password" placeholder="Digite uma senha forte" class="has-toggle" required @focus="isResetPasswordFocused = true" @blur="isResetPasswordFocused = false" />
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
            <label for="reset-password-confirm">Confirmar nova senha</label>
            <div class="input-with-toggle">
              <input id="reset-password-confirm" v-model="resetFlow.confirmPassword" :type="showResetConfirmPasswordField ? 'text' : 'password'" autocomplete="new-password" placeholder="Repita a nova senha" class="has-toggle" required />
              <button class="password-toggle" type="button" :aria-label="showResetConfirmPasswordField ? 'Ocultar senha' : 'Mostrar senha'" @click="showResetConfirmPasswordField = !showResetConfirmPasswordField">
                <svg v-if="showResetConfirmPasswordField" viewBox="0 0 24 24" fill="none" aria-hidden="true">
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
            <p v-if="resetCompromisedPasswordMessage" class="inline-hint hint-error">
              {{ resetCompromisedPasswordMessage }}
            </p>
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
                <p
                  v-if="resetFlow.error && !resetCompromisedPasswordMessage"
                  key="reset-password-error"
                  class="flash flash-error"
                >
                  {{ resetFlow.error }}
                </p>
                <span v-else key="reset-password-empty" class="feedback-empty" aria-hidden="true" />
              </Transition>
            </div>
            <button class="btn-primary" :class="{ 'is-loading': resetFlow.isCompleting }" type="submit" :disabled="resetFlow.isCompleting || !resetStrong || !resetPasswordsMatch"><span class="btn-spinner" aria-hidden="true" /><span class="btn-label">Atualizar senha</span></button>
          </form>
        </section>
      </Transition>
      </div>

      <div v-if="shouldShowSocial" class="auth-social-area">
        <div class="section-divider"><span>ou continue com</span></div>
        <button class="btn-microsoft" :class="{ 'is-loading': isMicrosoftSubmitting }" type="button" :disabled="isMicrosoftSubmitting || isGoogleSubmitting" @click="onSignInWithMicrosoft">
          <span class="btn-spinner" aria-hidden="true" />
          <span class="microsoft-icon" aria-hidden="true">
            <span class="microsoft-tile red" />
            <span class="microsoft-tile green" />
            <span class="microsoft-tile blue" />
            <span class="microsoft-tile yellow" />
          </span>
          <span class="btn-label">Continuar com Microsoft</span>
        </button>
        <button class="btn-google" :class="{ 'is-loading': isGoogleSubmitting }" type="button" :disabled="isGoogleSubmitting || isMicrosoftSubmitting" @click="onSignInWithGoogle">
          <span class="btn-spinner" aria-hidden="true" />
          <span class="google-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path fill="#EA4335" d="M12 10.2v3.9h5.5a4.7 4.7 0 0 1-2 3.1l3.1 2.4c1.8-1.7 2.9-4.2 2.9-7.2 0-.7-.1-1.5-.2-2.2H12Z" />
              <path fill="#34A853" d="M12 22c2.6 0 4.9-.9 6.5-2.4l-3.1-2.4c-.9.6-2 .9-3.4.9-2.6 0-4.8-1.7-5.5-4.1l-3.2 2.5A10 10 0 0 0 12 22Z" />
              <path fill="#4A90E2" d="M6.5 14c-.2-.6-.3-1.3-.3-2s.1-1.4.3-2L3.3 7.5A10 10 0 0 0 2 12c0 1.6.4 3.1 1.2 4.5L6.5 14Z" />
              <path fill="#FBBC05" d="M12 5.9c1.4 0 2.7.5 3.7 1.5l2.8-2.8A10 10 0 0 0 12 2C8 2 4.5 4.3 3.2 7.5L6.5 10c.7-2.4 2.9-4.1 5.5-4.1Z" />
            </svg>
          </span>
          <span class="btn-label">Continuar com Google</span>
        </button>
          </div>
        </section>
      </section>
    </div>

    <Transition name="fade-up">
      <div v-if="isCallbackProcessing" class="callback-overlay" aria-live="polite" aria-busy="true">
        <div class="callback-loader">
          <span class="ring-loader" />
        </div>
      </div>
    </Transition>
  </article>
</template>
