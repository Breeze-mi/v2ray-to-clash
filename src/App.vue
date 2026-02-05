<script setup lang="ts">
import { onMounted } from 'vue';
import {
  NConfigProvider,
  NLayout,
  NLayoutContent,
  NLayoutHeader,
  NGrid,
  NGridItem,
  NCard,
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
    primaryColor: '#5b8def',
    primaryColorHover: '#4a7de0',
    primaryColorPressed: '#3a6dd0',
    borderRadius: '8px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif',
  },
};
</script>

<template>
  <NConfigProvider :theme-overrides="themeOverrides">
    <NMessageProvider>
      <NLayout class="app-layout">
        <NLayoutHeader class="app-header" bordered>
          <div class="header-content">
            <div class="header-left">
              <div class="logo">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
                  <rect x="2" y="3" width="20" height="18" rx="3" stroke="#5b8def" stroke-width="2"/>
                  <path d="M7 8l3 4-3 4" stroke="#5b8def" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                  <path d="M13 16h4" stroke="#5b8def" stroke-width="2" stroke-linecap="round"/>
                </svg>
              </div>
              <div class="title-group">
                <h1 class="app-title">LocalSub</h1>
                <span class="app-subtitle">本地订阅转换器</span>
              </div>
            </div>
            <div class="header-right">
              <span class="version">v0.1.0</span>
              <span class="badge">Clash</span>
            </div>
          </div>
        </NLayoutHeader>

        <NLayoutContent class="app-content">
          <NGrid :cols="2" :x-gap="24" responsive="screen" item-responsive>
            <NGridItem span="2 m:1">
              <NCard title="配置" class="panel-card" :segmented="{ content: true }">
                <ConfigPanel />
              </NCard>
            </NGridItem>
            <NGridItem span="2 m:1">
              <NCard title="结果" class="panel-card" :segmented="{ content: true }">
                <ResultPanel />
              </NCard>
            </NGridItem>
          </NGrid>
        </NLayoutContent>

        <footer class="app-footer">
          <span>LocalSub - 零隐私泄露的订阅转换工具</span>
          <span class="separator">|</span>
          <span>所有转换均在本地 Rust 引擎完成</span>
        </footer>
      </NLayout>
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
  background: #f5f7fa;
  color: #1a1a2e;
}
</style>

<style scoped>
.app-layout {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.app-header {
  padding: 0 24px;
  height: 56px;
  display: flex;
  align-items: center;
  background: #fff;
  border-bottom: 1px solid #e8e8ec;
}

.header-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.logo {
  display: flex;
  align-items: center;
}

.title-group {
  display: flex;
  align-items: baseline;
  gap: 8px;
}

.app-title {
  font-size: 20px;
  font-weight: 700;
  color: #1a1a2e;
  letter-spacing: -0.02em;
}

.app-subtitle {
  font-size: 13px;
  color: #8c8c9a;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.version {
  font-size: 12px;
  color: #8c8c9a;
}

.badge {
  padding: 2px 10px;
  background: #eef3ff;
  color: #5b8def;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
}

.app-content {
  flex: 1;
  padding: 24px;
  overflow: auto;
}

.panel-card {
  height: calc(100vh - 56px - 48px - 40px);
}

.panel-card :deep(.n-card__content) {
  overflow: auto;
}

.app-footer {
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-size: 12px;
  color: #8c8c9a;
  background: #fff;
  border-top: 1px solid #e8e8ec;
}

.separator {
  opacity: 0.4;
}
</style>
