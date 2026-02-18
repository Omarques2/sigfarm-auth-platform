<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { authWebEnv } from "../config/env";
import { AuthApiError, authApiClient } from "../lib/auth-api";
import { resolveSafeReturnTo } from "../lib/return-to";

type AccountPhase = "loading" | "ready" | "error";
type EmailChangeStep = "idle" | "code";
type AccountProfile = {
  userId: string;
  email: string;
  emailVerified: boolean;
  displayName: string | null;
};

const route = useRoute();
const router = useRouter();

const phase = ref<AccountPhase>("loading");
const errorMessage = ref<string | null>(null);
const isSigningOut = ref(false);
const user = ref<AccountProfile | null>(null);
const profileName = ref("");
const profileFeedback = ref<{ type: "error" | "success"; message: string } | null>(null);
const isSavingProfile = ref(false);

const emailChange = reactive({
  step: "idle" as EmailChangeStep,
  newEmail: "",
  codeDigits: ["", "", "", "", "", ""] as string[],
  resendSeconds: 0,
  isRequesting: false,
  isConfirming: false,
  feedback: null as { type: "error" | "success"; message: string } | null,
});

const safeReturnTo = computed(() =>
  resolveSafeReturnTo({
    returnTo: firstQueryValue(route.query.returnTo),
    appBaseUrl: authWebEnv.authWebBaseUrl,
    defaultReturnTo: authWebEnv.defaultReturnTo,
    allowedOrigins: authWebEnv.allowedReturnOrigins,
  }),
);
const emailChangeCode = computed(() => emailChange.codeDigits.join(""));
const emailCodeRefs = ref<Array<HTMLInputElement | null>>([]);
let emailResendTimer: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  await loadAccountProfile();
});

onBeforeUnmount(() => {
  stopEmailResendCountdown();
});

async function loadAccountProfile(): Promise<void> {
  try {
    const profile = await authApiClient.getAccountProfile();
    user.value = profile;
    profileName.value = profile.displayName ?? "";
    phase.value = "ready";
  } catch (error) {
    if (error instanceof AuthApiError && error.status === 401) {
      await router.replace({
        name: "login",
        query: {
          returnTo: `${authWebEnv.authWebBaseUrl.replace(/\/$/, "")}/my-account/edit`,
        },
      });
      return;
    }
    phase.value = "error";
    errorMessage.value = error instanceof Error ? error.message : "Nao foi possivel carregar sua conta.";
  }
}

async function onSaveProfile(): Promise<void> {
  profileFeedback.value = null;
  const normalized = normalizeDisplayName(profileName.value);
  isSavingProfile.value = true;
  try {
    const updated = await authApiClient.updateAccountProfile({
      name: normalized,
    });
    if (!user.value) return;
    user.value = {
      ...user.value,
      displayName: updated.displayName,
    };
    profileName.value = updated.displayName ?? "";
    profileFeedback.value = {
      type: "success",
      message: "Perfil atualizado com sucesso.",
    };
  } catch (error) {
    profileFeedback.value = {
      type: "error",
      message: error instanceof Error ? error.message : "Falha ao atualizar perfil.",
    };
  } finally {
    isSavingProfile.value = false;
  }
}

async function onRequestEmailChangeCode(input?: { force?: boolean }): Promise<void> {
  if (!user.value) return;
  const force = Boolean(input?.force);
  emailChange.feedback = null;
  const newEmail = emailChange.newEmail.trim().toLowerCase();
  if (!newEmail || !isValidEmail(newEmail)) {
    emailChange.feedback = {
      type: "error",
      message: "Digite um email valido.",
    };
    return;
  }
  if (!force && emailChange.resendSeconds > 0) return;

  emailChange.isRequesting = true;
  try {
    const result = await authApiClient.requestEmailChangeCode(newEmail);
    if (result.status === "already_in_use") {
      emailChange.feedback = {
        type: "error",
        message: "Este email ja esta em uso por outra conta.",
      };
      return;
    }
    if (result.status === "same_as_current") {
      emailChange.feedback = {
        type: "error",
        message: "Digite um email diferente do atual.",
      };
      return;
    }

    emailChange.newEmail = newEmail;
    emailChange.step = "code";
    emailChange.codeDigits = ["", "", "", "", "", ""];
    startEmailResendCountdown(Math.max(1, result.retryAfterSeconds || 60));
    emailChange.feedback = {
      type: "success",
      message:
        result.status === "cooldown"
          ? "Aguarde o contador para reenviar o codigo."
          : "Codigo enviado para o novo email.",
    };
    await nextTick();
    focusEmailCodeInput(0);
  } catch (error) {
    emailChange.feedback = {
      type: "error",
      message: error instanceof Error ? error.message : "Falha ao enviar codigo.",
    };
  } finally {
    emailChange.isRequesting = false;
  }
}

async function onConfirmEmailChangeCode(): Promise<void> {
  emailChange.feedback = null;
  if (!/^\d{6}$/.test(emailChangeCode.value)) {
    emailChange.feedback = {
      type: "error",
      message: "Digite os 6 digitos do codigo.",
    };
    return;
  }

  emailChange.isConfirming = true;
  try {
    const result = await authApiClient.confirmEmailChangeCode({
      newEmail: emailChange.newEmail.trim().toLowerCase(),
      code: emailChangeCode.value,
    });
    if (!result.updated) {
      emailChange.feedback = {
        type: "error",
        message: resolveEmailChangeFailureMessage(result.reason),
      };
      return;
    }

    await loadAccountProfile();
    emailChange.step = "idle";
    emailChange.newEmail = "";
    emailChange.codeDigits = ["", "", "", "", "", ""];
    stopEmailResendCountdown();
    emailChange.feedback = {
      type: "success",
      message: "Email atualizado com sucesso.",
    };
  } catch (error) {
    emailChange.feedback = {
      type: "error",
      message: error instanceof Error ? error.message : "Falha ao confirmar codigo.",
    };
  } finally {
    emailChange.isConfirming = false;
  }
}

function onCancelEmailChange(): void {
  emailChange.step = "idle";
  emailChange.codeDigits = ["", "", "", "", "", ""];
  emailChange.feedback = null;
  stopEmailResendCountdown();
}

function setEmailCodeRef(el: Element | null, index: number): void {
  emailCodeRefs.value[index] = el instanceof HTMLInputElement ? el : null;
}

function onEmailCodeInput(index: number, event: Event): void {
  const target = event.target as HTMLInputElement;
  const value = target.value.replace(/\D/g, "").slice(-1);
  emailChange.codeDigits[index] = value;
  if (value && index < 5) focusEmailCodeInput(index + 1);
}

function onEmailCodeKeydown(index: number, event: KeyboardEvent): void {
  if (event.key === "Backspace" && !emailChange.codeDigits[index] && index > 0) {
    focusEmailCodeInput(index - 1);
  }
  if (event.key === "ArrowLeft" && index > 0) {
    event.preventDefault();
    focusEmailCodeInput(index - 1);
  }
  if (event.key === "ArrowRight" && index < 5) {
    event.preventDefault();
    focusEmailCodeInput(index + 1);
  }
}

function onEmailCodePaste(event: ClipboardEvent): void {
  const pasted = event.clipboardData?.getData("text") ?? "";
  const values = pasted.replace(/\D/g, "").slice(0, 6).split("");
  if (values.length === 0) return;
  event.preventDefault();
  for (let i = 0; i < 6; i += 1) emailChange.codeDigits[i] = values[i] ?? "";
  focusEmailCodeInput(Math.min(values.length, 6) - 1);
}

function focusEmailCodeInput(index: number): void {
  const input = emailCodeRefs.value[index];
  input?.focus();
  input?.select();
}

function startEmailResendCountdown(seconds: number): void {
  stopEmailResendCountdown();
  emailChange.resendSeconds = Math.max(0, Math.floor(seconds));
  if (emailChange.resendSeconds < 1) return;
  emailResendTimer = setInterval(() => {
    emailChange.resendSeconds = Math.max(0, emailChange.resendSeconds - 1);
    if (emailChange.resendSeconds <= 0) {
      stopEmailResendCountdown();
    }
  }, 1000);
}

function stopEmailResendCountdown(): void {
  if (emailResendTimer) clearInterval(emailResendTimer);
  emailResendTimer = null;
}

async function onSignOut(): Promise<void> {
  isSigningOut.value = true;
  try {
    await authApiClient.signOut();
    await router.replace({
      name: "login",
      query: {
        status: "signed-out",
      },
    });
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : "Falha ao encerrar sessao.";
  } finally {
    isSigningOut.value = false;
  }
}

function normalizeDisplayName(value: string): string | null {
  const normalized = value.trim().replace(/\s+/g, " ");
  if (!normalized) return null;
  return normalized.slice(0, 120);
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function resolveEmailChangeFailureMessage(reason: string | undefined): string {
  if (reason === "already_in_use") return "Este email ja esta em uso por outra conta.";
  if (reason === "same_as_current") return "Digite um email diferente do atual.";
  return "Codigo invalido ou expirado. Solicite um novo codigo.";
}

function firstQueryValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}
</script>

<template>
  <article class="view panel-screen account-view">
    <header class="brand-hero" aria-label="Sigfarm Intelligence">
      <div class="brand-logo-large-frame">
        <img src="/sigfarm-logo.png" alt="Sigfarm Intelligence" class="brand-logo-large" />
      </div>
      <p class="brand-company">Sigfarm Intelligence</p>
    </header>

    <section v-if="phase === 'loading'" class="account-state-card">
      <span class="ring-loader" aria-hidden="true" />
      <p class="loading-pulse">Carregando sua conta...</p>
    </section>

    <section v-else-if="phase === 'error'" class="account-state-card account-error-card">
      <h1>Minha Conta</h1>
      <p class="flash flash-error">{{ errorMessage ?? "Falha ao carregar conta." }}</p>
      <RouterLink class="link-like" to="/login">Voltar para login</RouterLink>
    </section>

    <section v-else class="account-content">
      <div class="account-headline">
        <h1>Editar Conta</h1>
        <p class="step-caption">Atualize nome e email com verificacao por codigo.</p>
      </div>

      <div class="account-grid">
        <article class="account-card">
          <h2>Perfil</h2>
          <form class="account-form-grid" @submit.prevent="onSaveProfile">
            <label>
              Nome
              <input
                v-model="profileName"
                type="text"
                autocomplete="name"
                placeholder="Como voce prefere ser chamado"
              />
            </label>
            <button
              class="btn-primary"
              :class="{ 'is-loading': isSavingProfile }"
              type="submit"
              :disabled="isSavingProfile"
            >
              <span class="btn-spinner" aria-hidden="true" />
              <span class="btn-label">Salvar nome</span>
            </button>
          </form>
          <p
            v-if="profileFeedback"
            class="flash"
            :class="profileFeedback.type === 'error' ? 'flash-error' : 'flash-success'"
          >
            {{ profileFeedback.message }}
          </p>
        </article>

        <article class="account-card">
          <h2>Email</h2>
          <dl class="account-details">
            <div>
              <dt>Email atual</dt>
              <dd>{{ user?.email }}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                <span class="status-pill" :class="user?.emailVerified ? 'is-success' : 'is-warning'">
                  {{ user?.emailVerified ? "Verificado" : "Pendente" }}
                </span>
              </dd>
            </div>
          </dl>

          <div class="account-email-flow">
            <label>
              Novo email
              <input
                v-model.trim="emailChange.newEmail"
                type="email"
                autocomplete="email"
                placeholder="novo.email@empresa.com"
                :disabled="emailChange.step === 'code'"
              />
            </label>

            <div v-if="emailChange.step === 'code'" class="otp-grid" @paste="onEmailCodePaste">
              <input
                v-for="(_, index) in emailChange.codeDigits"
                :key="`email-change-otp-${index}`"
                :ref="(el) => setEmailCodeRef(el as Element | null, index)"
                :value="emailChange.codeDigits[index]"
                inputmode="numeric"
                maxlength="1"
                autocomplete="one-time-code"
                class="otp-input"
                @input="onEmailCodeInput(index, $event)"
                @keydown="onEmailCodeKeydown(index, $event)"
              />
            </div>

            <p
              v-if="emailChange.feedback"
              class="flash"
              :class="emailChange.feedback.type === 'error' ? 'flash-error' : 'flash-success'"
            >
              {{ emailChange.feedback.message }}
            </p>

            <div class="account-flow-actions">
              <button
                v-if="emailChange.step === 'idle'"
                class="btn-primary"
                :class="{ 'is-loading': emailChange.isRequesting }"
                type="button"
                :disabled="emailChange.isRequesting"
                @click="onRequestEmailChangeCode({ force: true })"
              >
                <span class="btn-spinner" aria-hidden="true" />
                <span class="btn-label">Enviar codigo</span>
              </button>

              <template v-else>
                <button
                  class="btn-primary"
                  :class="{ 'is-loading': emailChange.isConfirming }"
                  type="button"
                  :disabled="emailChange.isConfirming"
                  @click="onConfirmEmailChangeCode"
                >
                  <span class="btn-spinner" aria-hidden="true" />
                  <span class="btn-label">Confirmar email</span>
                </button>

                <button
                  class="btn-ghost"
                  :class="{ 'is-loading': emailChange.isRequesting }"
                  type="button"
                  :disabled="emailChange.isRequesting || emailChange.resendSeconds > 0"
                  @click="onRequestEmailChangeCode()"
                >
                  <span class="btn-spinner" aria-hidden="true" />
                  <span class="btn-label">
                    {{ emailChange.resendSeconds > 0 ? `Reenviar em ${emailChange.resendSeconds}s` : "Reenviar codigo" }}
                  </span>
                </button>

                <button class="link-like" type="button" @click="onCancelEmailChange">Cancelar</button>
              </template>
            </div>
          </div>
        </article>
      </div>

      <p v-if="errorMessage" class="flash flash-error">{{ errorMessage }}</p>

      <footer class="account-actions">
        <RouterLink class="link-like" to="/my-account">Voltar para minha conta</RouterLink>
        <button class="btn-ghost" :class="{ 'is-loading': isSigningOut }" type="button" :disabled="isSigningOut" @click="onSignOut">
          <span class="btn-spinner" aria-hidden="true" />
          <span class="btn-label">Encerrar sessao</span>
        </button>
      </footer>
    </section>
  </article>
</template>
