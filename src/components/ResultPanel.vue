<script setup lang="ts">
import { computed } from 'vue';
import {
  NButton,
  NCode,
  NScrollbar,
  NStatistic,
  NSpace,
  NGrid,
  NGridItem,
  NAlert,
  NIcon,
  NTooltip,
  useMessage,
} from 'naive-ui';
import {
  CopyOutline,
  DownloadOutline,
  CheckmarkCircleOutline,
  WarningOutline,
} from '@vicons/ionicons5';
import { useAppStore } from '../stores/app';

const store = useAppStore();
const message = useMessage();

const yamlPreview = computed(() => {
  if (!store.result) return '';
  return store.result.yaml;
});

async function copyToClipboard() {
  if (!store.result) return;
  try {
    await navigator.clipboard.writeText(store.result.yaml);
    message.success('已复制到剪贴板');
  } catch {
    message.error('复制失败');
  }
}

function downloadYaml() {
  if (!store.result) return;
  const blob = new Blob([store.result.yaml], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'clash-config.yaml';
  a.click();
  URL.revokeObjectURL(url);
  message.success('已下载配置文件');
}
</script>

<template>
  <div class="result-panel">
    <!-- Empty state -->
    <div v-if="!store.result && !store.error && !store.loading" class="empty-state">
      <div class="empty-icon">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="16" y1="13" x2="8" y2="13" />
          <line x1="16" y1="17" x2="8" y2="17" />
          <polyline points="10 9 9 9 8 9" />
        </svg>
      </div>
      <p class="empty-text">在左侧输入订阅链接，点击"转换订阅"</p>
      <p class="empty-subtext">生成的 Clash 配置将在这里显示</p>
    </div>

    <!-- Loading state -->
    <div v-if="store.loading" class="loading-state">
      <div class="spinner"></div>
      <p>正在转换中...</p>
    </div>

    <!-- Error state -->
    <NAlert v-if="store.error" type="error" closable @close="store.error = null">
      <template #header>转换失败</template>
      {{ store.error }}
    </NAlert>

    <!-- Result -->
    <div v-if="store.result" class="result-content">
      <!-- Stats bar -->
      <div class="stats-bar">
        <NGrid :cols="4" :x-gap="12">
          <NGridItem>
            <NStatistic label="解析节点" :value="store.result.node_count" />
          </NGridItem>
          <NGridItem>
            <NStatistic label="过滤后" :value="store.result.filtered_count" />
          </NGridItem>
          <NGridItem>
            <NStatistic label="策略组" :value="store.result.group_count" />
          </NGridItem>
          <NGridItem>
            <NStatistic label="规则数" :value="store.result.rule_count" />
          </NGridItem>
        </NGrid>
      </div>

      <!-- Warnings -->
      <NAlert
        v-for="(warning, idx) in store.result.warnings"
        :key="idx"
        type="warning"
        class="warning-alert"
      >
        <template #icon>
          <NIcon><WarningOutline /></NIcon>
        </template>
        {{ warning }}
      </NAlert>

      <!-- Toolbar -->
      <div class="toolbar">
        <NSpace>
          <NTooltip>
            <template #trigger>
              <NButton size="small" @click="copyToClipboard">
                <template #icon>
                  <NIcon><CopyOutline /></NIcon>
                </template>
                复制
              </NButton>
            </template>
            复制 YAML 配置到剪贴板
          </NTooltip>
          <NTooltip>
            <template #trigger>
              <NButton size="small" @click="downloadYaml">
                <template #icon>
                  <NIcon><DownloadOutline /></NIcon>
                </template>
                下载
              </NButton>
            </template>
            下载为 clash-config.yaml
          </NTooltip>
        </NSpace>
        <span class="success-badge">
          <NIcon size="16" color="#18a058"><CheckmarkCircleOutline /></NIcon>
          转换成功
        </span>
      </div>

      <!-- YAML Preview -->
      <div class="yaml-preview">
        <NScrollbar style="max-height: calc(100vh - 380px)">
          <NCode :code="yamlPreview" language="yaml" word-wrap />
        </NScrollbar>
      </div>
    </div>
  </div>
</template>

<style scoped>
.result-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  min-height: 400px;
  color: var(--text-color-3);
}

.empty-icon {
  opacity: 0.3;
  margin-bottom: 16px;
}

.empty-text {
  font-size: 16px;
  margin: 0 0 4px 0;
}

.empty-subtext {
  font-size: 13px;
  margin: 0;
  opacity: 0.7;
}

.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  min-height: 400px;
  gap: 16px;
  color: var(--text-color-2);
}

.spinner {
  width: 36px;
  height: 36px;
  border: 3px solid var(--divider-color);
  border-top-color: var(--primary-color);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.result-content {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.stats-bar {
  padding: 12px 16px;
  background: var(--card-color);
  border-radius: 8px;
  border: 1px solid var(--border-color);
}

.stats-bar :deep(.n-statistic .n-statistic-value) {
  font-size: 20px;
}

.stats-bar :deep(.n-statistic .n-statistic__label) {
  font-size: 12px;
}

.warning-alert {
  margin-bottom: 4px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.success-badge {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: #18a058;
}

.yaml-preview {
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
  background: var(--code-color);
}

.yaml-preview :deep(.n-code) {
  padding: 16px;
  font-size: 12px;
  line-height: 1.6;
}
</style>
