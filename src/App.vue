<script setup lang="ts">
import { onMounted } from 'vue';
import {
  NConfigProvider,
  NMessageProvider,
  type GlobalThemeOverrides,
} from 'naive-ui';
import { useAppStore } from './stores/app';
import ConfigPanel from './components/ConfigPanel.vue';
import ResultPanel from './components/ResultPanel.vue';

const store = useAppStore();

onMounted(() => {
  store.loadPresets();
});

const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: '#6366f1',
    primaryColorHover: '#4f46e5',
    primaryColorPressed: '#4338ca',
    borderRadius: '6px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif',
  },
  Card: {
    paddingSmall: '12px',
    paddingMedium: '16px',
  },
  Input: {
    heightSmall: '28px',
    heightMedium: '32px',
  },
  Button: {
    heightSmall: '28px',
    heightMedium: '32px',
  },
};
</script>

<template>
  <NConfigProvider :theme-overrides="themeOverrides">
    <NMessageProvider>
      <div class="h-screen flex flex-col bg-slate-50 overflow-hidden">
        <!-- Header -->
        <header class="h-11 px-4 flex items-center justify-between bg-white border-b border-slate-200 shrink-0">
          <div class="flex items-center gap-2.5">
            <!-- Logo -->
            <div class="w-6 h-6 rounded-md bg-gradient-to-br from-indigo-500 to-indigo-600 flex items-center justify-center shadow-sm">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" class="text-white">
                <path d="M7 8l3 4-3 4" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M13 16h4" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
              </svg>
            </div>
            <h1 class="text-base font-bold text-slate-800 tracking-tight">LocalSub</h1>
            <span class="px-2 py-0.5 bg-gradient-to-r from-indigo-50 to-indigo-100 text-indigo-600 rounded-full text-xs font-semibold">
              Clash/Mihomo
            </span>
          </div>
          <span class="text-xs text-slate-400 font-medium">v0.1.2</span>
        </header>

        <!-- Main Content -->
        <main class="flex-1 flex overflow-hidden">
          <!-- Config Panel (40%) -->
          <aside class="w-2/5 min-w-0 bg-white border-r border-slate-200 flex flex-col overflow-hidden">
            <div class="px-3 pt-3 pb-2">
              <h2 class="text-xs font-semibold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                <span class="i-carbon-settings w-3.5 h-3.5"></span>
                配置
              </h2>
            </div>
            <div class="flex-1 overflow-y-auto px-3 pb-3">
              <ConfigPanel />
            </div>
          </aside>

          <!-- Result Panel (60%) -->
          <section class="w-3/5 min-w-0 bg-slate-50 flex flex-col overflow-hidden">
            <div class="px-4 pt-3 pb-2">
              <h2 class="text-xs font-semibold text-slate-500 uppercase tracking-wide flex items-center gap-1.5">
                <span class="i-carbon-document w-3.5 h-3.5"></span>
                结果
              </h2>
            </div>
            <div class="flex-1 overflow-y-auto px-4 pb-3">
              <ResultPanel />
            </div>
          </section>
        </main>
      </div>
    </NMessageProvider>
  </NConfigProvider>
</template>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  height: 100%;
  overflow: hidden;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
  font-size: 13px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* 自定义滚动条 */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: transparent;
}

::-webkit-scrollbar-thumb {
  background: #cbd5e1;
  border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
  background: #94a3b8;
}
</style>
