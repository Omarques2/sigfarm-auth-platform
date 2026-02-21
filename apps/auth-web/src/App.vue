<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";

const route = useRoute();

const isLoginSurface = computed(() => route.name === "login" || route.name === "auth-callback");
const panelRef = ref<HTMLElement | null>(null);
const panelScale = ref(1);
const panelStyle = computed(() => ({
  "--panel-scale": panelScale.value.toString(),
}));

let resizeObserver: ResizeObserver | null = null;
let rafId: number | null = null;

watch(
  () => route.fullPath,
  () => {
    scheduleScaleUpdate();
  },
);

onMounted(() => {
  scheduleScaleUpdate();
  window.addEventListener("resize", scheduleScaleUpdate, { passive: true });
  window.addEventListener("orientationchange", scheduleScaleUpdate, { passive: true });

  if (typeof ResizeObserver !== "undefined") {
    resizeObserver = new ResizeObserver(() => {
      scheduleScaleUpdate();
    });
    if (panelRef.value) {
      resizeObserver.observe(panelRef.value);
    }
  }
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", scheduleScaleUpdate);
  window.removeEventListener("orientationchange", scheduleScaleUpdate);
  if (resizeObserver) {
    resizeObserver.disconnect();
    resizeObserver = null;
  }
  if (rafId !== null) {
    window.cancelAnimationFrame(rafId);
    rafId = null;
  }
});

function scheduleScaleUpdate(): void {
  if (rafId !== null) {
    window.cancelAnimationFrame(rafId);
  }
  rafId = window.requestAnimationFrame(() => {
    rafId = null;
    void updateScale();
  });
}

async function updateScale(): Promise<void> {
  await nextTick();
  const panel = panelRef.value;
  if (!panel) return;

  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  const horizontalPadding = viewportWidth <= 420 ? 0 : viewportWidth <= 640 ? 12 : 24;
  const verticalPadding = viewportHeight <= 700 ? 0 : viewportHeight <= 820 ? 8 : 20;
  const availableWidth = Math.max(1, viewportWidth - horizontalPadding * 2);
  const availableHeight = Math.max(1, viewportHeight - verticalPadding * 2);
  const naturalWidth = Math.max(1, panel.scrollWidth);
  const naturalHeight = Math.max(1, panel.scrollHeight);

  const targetScale = Math.min(1, availableWidth / naturalWidth, availableHeight / naturalHeight);
  const nextScale = Math.max(0.55, Number(targetScale.toFixed(4)));
  if (Math.abs(nextScale - panelScale.value) < 0.008) return;
  panelScale.value = nextScale;
}
</script>

<template>
  <main class="auth-shell">
    <div class="auth-panel-stage">
      <section
        ref="panelRef"
        class="auth-panel"
        :class="{ 'auth-panel-login': isLoginSurface }"
        :style="panelStyle"
      >
        <RouterView v-slot="{ Component, route: currentRoute }">
          <Transition name="route-panel">
            <component :is="Component" :key="currentRoute.path" />
          </Transition>
        </RouterView>
      </section>
    </div>
  </main>
</template>
