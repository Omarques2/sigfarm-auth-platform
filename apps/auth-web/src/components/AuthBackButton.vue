<script setup lang="ts">
import { RouterLink } from "vue-router";
import type { RouteLocationRaw } from "vue-router";

const props = withDefaults(
  defineProps<{
    label?: string;
    to?: RouteLocationRaw;
    ariaLabel?: string;
  }>(),
  {
    label: "Voltar",
  },
);

defineEmits<{
  click: [];
}>();
</script>

<template>
  <div class="back-nav-shell">
    <RouterLink v-if="to" class="back-nav-button" :to="to" :aria-label="ariaLabel ?? label">
      <span class="back-nav-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M15 6 9 12l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </span>
      <span class="back-nav-text">{{ label }}</span>
    </RouterLink>

    <button v-else class="back-nav-button" type="button" :aria-label="ariaLabel ?? label" @click="$emit('click')">
      <span class="back-nav-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M15 6 9 12l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </span>
      <span class="back-nav-text">{{ label }}</span>
    </button>
  </div>
</template>
