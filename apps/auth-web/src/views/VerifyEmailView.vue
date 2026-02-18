<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { authApiClient, AuthApiError } from "../lib/auth-api";

const route = useRoute();
const router = useRouter();

const phase = ref<"processing" | "success" | "error">("processing");
const detail = ref("Validando seu link de verificacao...");
const redirectSeconds = ref(4);

let redirectTimer: ReturnType<typeof setInterval> | null = null;
let redirectTimeout: ReturnType<typeof setTimeout> | null = null;

onMounted(async () => {
  const token = firstQueryValue(route.query.token) ?? firstQueryValue(route.query.Token);
  if (!token) {
    phase.value = "error";
    detail.value = "Link invalido. Solicite um novo email de verificacao.";
    return;
  }

  try {
    await authApiClient.verifyEmail(token);
    phase.value = "success";
    detail.value = "Email validado com sucesso.";
    scheduleLoginRedirect();
  } catch (error) {
    phase.value = "error";
    detail.value = resolveErrorMessage(error);
  }
});

onBeforeUnmount(() => {
  if (redirectTimer) clearInterval(redirectTimer);
  if (redirectTimeout) clearTimeout(redirectTimeout);
});

function scheduleLoginRedirect(): void {
  redirectTimeout = setTimeout(() => {
    void router.replace({
      name: "login",
      query: {
        status: "email-verified",
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

function resolveErrorMessage(error: unknown): string {
  if (error instanceof AuthApiError) {
    if (error.status === 400 || error.status === 401) {
      return "Token invalido ou expirado. Solicite um novo email de verificacao.";
    }
    if (error.status === 429) {
      return "Muitas tentativas em pouco tempo. Aguarde e tente novamente.";
    }
    return error.message || "Falha ao verificar email.";
  }
  if (error instanceof Error && error.message) return error.message;
  return "Falha ao verificar email.";
}
</script>

<template>
  <article class="view panel-screen verify-view">
    <header class="brand-header">
      <div class="brand-logo-frame">
        <img src="/sigfarm-logo.png" alt="Sigfarm" class="brand-logo" />
      </div>
      <div class="brand-labels">
        <strong>sigfarm</strong>
        <small>identity</small>
      </div>
    </header>

    <section class="step-block verify-step">
      <h1>Verificar email</h1>
      <p class="step-caption">Concluindo a validacao da sua conta.</p>

      <div class="verify-state-card" :class="`is-${phase}`">
        <div class="verify-icon" aria-hidden="true">
          <svg v-if="phase === 'success'" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8" />
            <path d="M8 12.5 10.8 15.2 16.2 9.8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
          <svg v-else-if="phase === 'error'" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8" />
            <path d="m9 9 6 6M15 9l-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
          </svg>
          <span v-else class="ring-loader" />
        </div>

        <p :class="{ 'loading-pulse': phase === 'processing' }">{{ detail }}</p>

        <p v-if="phase === 'success'" class="verify-next">Voltando para login em {{ redirectSeconds }}s...</p>
      </div>

      <div class="verify-actions">
        <RouterLink v-if="phase !== 'processing'" class="link-like" to="/login">Ir para login</RouterLink>
      </div>
    </section>
  </article>
</template>
