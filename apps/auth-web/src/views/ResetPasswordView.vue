<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { authApiClient, AuthApiError } from "../lib/auth-api";

type PasswordRule = {
  key: string;
  label: string;
  met: boolean;
};

const route = useRoute();
const router = useRouter();
const isSubmitting = ref(false);
const showPasswordField = ref(false);
const flashError = ref<string | null>(null);
const flashSuccess = ref<string | null>(null);
const redirectSeconds = ref(4);

let redirectTimer: ReturnType<typeof setInterval> | null = null;
let redirectTimeout: ReturnType<typeof setTimeout> | null = null;

const form = reactive({
  password: "",
});

const token = computed(() => firstQueryValue(route.query.token));
const hasToken = computed(() => Boolean(token.value));
const passwordRules = computed(() => buildPasswordRules(form.password));
const isStrongPassword = computed(() => passwordRules.value.every((rule) => rule.met));
const showChecklist = computed(() => form.password.trim().length > 0);

onBeforeUnmount(() => {
  if (redirectTimer) clearInterval(redirectTimer);
  if (redirectTimeout) clearTimeout(redirectTimeout);
});

async function onSubmit(): Promise<void> {
  flashError.value = null;
  flashSuccess.value = null;

  if (!token.value) {
    flashError.value = "Token de redefinicao ausente.";
    return;
  }
  if (!isStrongPassword.value) {
    flashError.value = "Use uma senha forte para continuar.";
    return;
  }

  isSubmitting.value = true;
  try {
    await authApiClient.resetPassword(token.value, form.password);
    flashSuccess.value = "Senha alterada com sucesso.";
    scheduleLoginRedirect();
    form.password = "";
  } catch (error) {
    flashError.value = resolveErrorMessage(error);
  } finally {
    isSubmitting.value = false;
  }
}

function scheduleLoginRedirect(): void {
  if (redirectTimeout) clearTimeout(redirectTimeout);
  if (redirectTimer) clearInterval(redirectTimer);
  redirectSeconds.value = 4;

  redirectTimeout = setTimeout(() => {
    void router.replace({
      name: "login",
      query: {
        status: "password-updated",
      },
    });
  }, 4000);

  redirectTimer = setInterval(() => {
    redirectSeconds.value = Math.max(0, redirectSeconds.value - 1);
    if (redirectSeconds.value === 0 && redirectTimer) {
      clearInterval(redirectTimer);
      redirectTimer = null;
    }
  }, 1000);
}

function firstQueryValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}

function buildPasswordRules(password: string): PasswordRule[] {
  return [
    {
      key: "length",
      label: "Minimo de 12 caracteres",
      met: password.length >= 12,
    },
    {
      key: "lowercase",
      label: "Pelo menos 1 letra minuscula",
      met: /[a-z]/.test(password),
    },
    {
      key: "uppercase",
      label: "Pelo menos 1 letra maiuscula",
      met: /[A-Z]/.test(password),
    },
    {
      key: "digit",
      label: "Pelo menos 1 numero",
      met: /\d/.test(password),
    },
    {
      key: "special",
      label: "Pelo menos 1 caractere especial",
      met: /[^A-Za-z\d]/.test(password),
    },
  ];
}

function resolveErrorMessage(error: unknown): string {
  if (error instanceof AuthApiError) {
    if (error.status === 400 || error.status === 401) return "Token invalido ou expirado.";
    if (error.status === 429) return "Muitas tentativas. Aguarde e tente novamente.";
    return error.message || "Nao foi possivel redefinir a senha.";
  }
  if (error instanceof Error && error.message) return error.message;
  return "Nao foi possivel redefinir a senha.";
}
</script>

<template>
  <article class="view panel-screen">
    <header class="brand-hero" aria-label="Sigfarm Intelligence">
      <div class="brand-logo-large-frame">
        <img src="/sigfarm-logo.png" alt="Sigfarm Intelligence" class="brand-logo-large" />
      </div>
      <p class="brand-company">Sigfarm Intelligence</p>
    </header>

    <section class="login-content-zone">
      <div class="step-block">
        <h1>Nova senha</h1>
        <p class="step-caption">Defina uma nova senha para continuar.</p>

        <p v-if="!hasToken" class="flash flash-error">
          Link invalido. Solicite um novo email de recuperacao.
        </p>

        <form v-else class="form-grid" @submit.prevent="onSubmit">
          <label>
            Nova senha
            <div class="input-with-toggle">
              <input
                v-model="form.password"
                :type="showPasswordField ? 'text' : 'password'"
                class="has-toggle"
                autocomplete="new-password"
                placeholder="Digite uma senha forte"
                required
              />
              <button
                class="password-toggle"
                type="button"
                :aria-label="showPasswordField ? 'Ocultar senha' : 'Mostrar senha'"
                @click="showPasswordField = !showPasswordField"
              >
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

          <div class="password-checklist-slot" :class="{ visible: showChecklist }" aria-live="polite">
            <TransitionGroup
              v-if="showChecklist"
              name="check-item"
              tag="ul"
              class="password-checklist signup-checklist"
            >
              <li
                v-for="(rule, index) in passwordRules"
                :key="`reset-link-${rule.key}`"
                class="password-rule"
                :class="rule.met ? 'met' : 'unmet'"
                :style="{ '--stagger-delay': `${index * 55}ms` }"
              >
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

          <button
            class="btn-primary"
            :class="{ 'is-loading': isSubmitting }"
            type="submit"
            :disabled="isSubmitting || !isStrongPassword"
          >
            <span class="btn-spinner" aria-hidden="true" />
            <span class="btn-label">Atualizar senha</span>
          </button>
        </form>

        <p v-if="flashError" class="flash flash-error">{{ flashError }}</p>
        <p v-if="flashSuccess" class="flash flash-success">
          {{ flashSuccess }}
          <span class="inline-hint"> Redirecionando em {{ redirectSeconds }}s...</span>
        </p>

        <p class="helper-row single">
          <RouterLink class="link-like" to="/login">Voltar para login</RouterLink>
        </p>
      </div>
    </section>
  </article>
</template>
