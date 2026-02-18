<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { authWebEnv } from "../config/env";
import { AuthApiError, authApiClient } from "../lib/auth-api";
import { resolveSafeReturnTo } from "../lib/return-to";

type AccountPhase = "loading" | "ready" | "error";
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

const safeReturnTo = computed(() =>
  resolveSafeReturnTo({
    returnTo: firstQueryValue(route.query.returnTo),
    appBaseUrl: authWebEnv.authWebBaseUrl,
    defaultReturnTo: authWebEnv.defaultReturnTo,
    allowedOrigins: authWebEnv.allowedReturnOrigins,
  }),
);

onMounted(async () => {
  await loadAccountProfile();
});

async function loadAccountProfile(): Promise<void> {
  try {
    const profile = await authApiClient.getAccountProfile();
    user.value = profile;
    phase.value = "ready";
  } catch (error) {
    if (error instanceof AuthApiError && error.status === 401) {
      await router.replace({
        name: "login",
        query: {
          returnTo: `${authWebEnv.authWebBaseUrl.replace(/\/$/, "")}/my-account`,
        },
      });
      return;
    }
    phase.value = "error";
    errorMessage.value = error instanceof Error ? error.message : "Nao foi possivel carregar sua conta.";
  }
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
      <div class="account-headline-row">
        <div class="account-headline">
          <h1>Minha Conta</h1>
          <p class="step-caption">Resumo da conta e acessos.</p>
        </div>
        <RouterLink class="account-icon-link" to="/my-account/edit" aria-label="Editar dados da conta" title="Editar dados da conta">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M4 20h4l10-10-4-4L4 16v4Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" />
            <path d="m12.8 7.2 4 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
          </svg>
        </RouterLink>
      </div>

      <div class="account-grid">
        <article class="account-card">
          <h2>Perfil</h2>
          <dl class="account-details">
            <div>
              <dt>Nome</dt>
              <dd>{{ user?.displayName || "-" }}</dd>
            </div>
            <div>
              <dt>Email</dt>
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
        </article>
      </div>

      <p v-if="errorMessage" class="flash flash-error">{{ errorMessage }}</p>

      <footer class="account-actions">
        <a class="link-like" :href="safeReturnTo">Voltar para aplicacao</a>
        <button class="btn-ghost" :class="{ 'is-loading': isSigningOut }" type="button" :disabled="isSigningOut" @click="onSignOut">
          <span class="btn-spinner" aria-hidden="true" />
          <span class="btn-label">Encerrar sessao</span>
        </button>
      </footer>
    </section>
  </article>
</template>
