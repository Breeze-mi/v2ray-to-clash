<script setup lang="ts">
import { computed } from 'vue';
import {
  NButton,
  NCode,
  NScrollbar,
  NAlert,
  NIcon,
  NTooltip,
  NProgress,
  useMessage,
} from 'naive-ui';
import {
  CopyOutline,
  DownloadOutline,
  TrashOutline,
  CheckmarkCircleOutline,
  WarningOutline,
} from '@vicons/ionicons5';
import { useAppStore } from '../stores/app';
import { formatBytes, formatExpire } from '../utils/format';

const store = useAppStore();
const message = useMessage();

const yamlPreview = computed(() => {
  if (!store.result) return '';
  return store.result.yaml;
});

const usedPercentage = computed(() => {
  const info = store.result?.subscription_info;
  if (!info || !info.total || info.total === 0) return null;
  const used = (info.upload || 0) + (info.download || 0);
  return Math.min(100, Math.round((used / info.total) * 100));
});

const usedTraffic = computed(() => {
  const info = store.result?.subscription_info;
  if (!info) return 0;
  return (info.upload || 0) + (info.download || 0);
});

const hasSubscriptionInfo = computed(() => {
  const info = store.result?.subscription_info;
  return info && (info.total || info.expire);
});

// 统计数据（始终显示）
const stats = computed(() => ({
  nodeCount: store.result?.node_count ?? '-',
  filteredCount: store.result?.filtered_count ?? '-',
  groupCount: store.result?.group_count ?? '-',
  ruleCount: store.result?.rule_count ?? '-',
}));

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
  <div class="flex flex-col h-full gap-3">
    <!-- 统计卡片 - 始终显示 -->
    <div class="grid grid-cols-4 gap-2 shrink-0">
      <div class="bg-white rounded-lg border border-slate-200 p-2.5 text-center shadow-sm hover:shadow transition-shadow">
        <div class="text-lg font-bold text-slate-800" :class="{ 'text-slate-300': !store.result }">
          {{ stats.nodeCount }}
        </div>
        <div class="text-xs text-slate-500 flex items-center justify-center gap-1">
          <span class="i-carbon-cube w-3 h-3 text-slate-400"></span>
          解析节点
        </div>
      </div>
      <div class="bg-white rounded-lg border border-slate-200 p-2.5 text-center shadow-sm hover:shadow transition-shadow">
        <div class="text-lg font-bold" :class="store.result ? 'text-indigo-600' : 'text-slate-300'">
          {{ stats.filteredCount }}
        </div>
        <div class="text-xs text-slate-500 flex items-center justify-center gap-1">
          <span class="i-carbon-filter w-3 h-3 text-slate-400"></span>
          过滤后
        </div>
      </div>
      <div class="bg-white rounded-lg border border-slate-200 p-2.5 text-center shadow-sm hover:shadow transition-shadow">
        <div class="text-lg font-bold text-slate-800" :class="{ 'text-slate-300': !store.result }">
          {{ stats.groupCount }}
        </div>
        <div class="text-xs text-slate-500 flex items-center justify-center gap-1">
          <span class="i-carbon-folder w-3 h-3 text-slate-400"></span>
          策略组
        </div>
      </div>
      <div class="bg-white rounded-lg border border-slate-200 p-2.5 text-center shadow-sm hover:shadow transition-shadow">
        <div class="text-lg font-bold text-slate-800" :class="{ 'text-slate-300': !store.result }">
          {{ stats.ruleCount }}
        </div>
        <div class="text-xs text-slate-500 flex items-center justify-center gap-1">
          <span class="i-carbon-rule w-3 h-3 text-slate-400"></span>
          规则数
        </div>
      </div>
    </div>

    <!-- 错误状态 -->
    <NAlert v-if="store.error" type="error" closable @close="store.error = null" class="shrink-0">
      <template #header>转换失败</template>
      {{ store.error }}
    </NAlert>

    <!-- 主内容区 -->
    <div class="flex-1 min-h-0 flex flex-col bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
      <!-- 工具栏 - 始终显示 -->
      <div class="flex justify-between items-center px-3 py-2 border-b border-slate-100 bg-slate-50/50 shrink-0">
        <div class="flex gap-2">
          <NTooltip>
            <template #trigger>
              <NButton size="small" :disabled="!store.result" @click="copyToClipboard">
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
              <NButton size="small" :disabled="!store.result" @click="downloadYaml">
                <template #icon>
                  <NIcon><DownloadOutline /></NIcon>
                </template>
                下载
              </NButton>
            </template>
            下载为 clash-config.yaml
          </NTooltip>
          <NTooltip>
            <template #trigger>
              <NButton size="small" :disabled="!store.result" @click="store.clearResult">
                <template #icon>
                  <NIcon><TrashOutline /></NIcon>
                </template>
                清空
              </NButton>
            </template>
            清空当前配置
          </NTooltip>
        </div>
        <span v-if="store.result" class="flex items-center gap-1 text-xs text-emerald-600 font-medium">
          <NIcon size="14" color="#10b981"><CheckmarkCircleOutline /></NIcon>
          转换成功
        </span>
        <span v-else class="text-xs text-slate-400">等待转换</span>
      </div>

      <!-- 订阅信息 -->
      <div v-if="hasSubscriptionInfo" class="px-3 py-2 border-b border-slate-100 bg-gradient-to-r from-blue-50/80 to-indigo-50/80 shrink-0">
        <div class="flex items-center justify-between mb-1.5">
          <span class="flex items-center gap-1 text-xs font-medium text-blue-600">
            <span class="i-carbon-cloud-download w-3.5 h-3.5"></span>
            订阅信息
          </span>
          <span class="text-xs text-slate-500 flex items-center gap-1">
            <span class="i-carbon-time w-3 h-3"></span>
            {{ formatExpire(store.result?.subscription_info?.expire) }}
          </span>
        </div>
        <div class="flex items-center gap-2">
          <div class="flex-1">
            <NProgress
              v-if="usedPercentage !== null"
              type="line"
              :percentage="usedPercentage"
              :show-indicator="false"
              :height="6"
              :border-radius="3"
              :color="usedPercentage > 90 ? '#ef4444' : usedPercentage > 70 ? '#f59e0b' : '#10b981'"
              :rail-color="'#e2e8f0'"
            />
          </div>
          <span class="text-xs text-slate-600 whitespace-nowrap">
            {{ formatBytes(usedTraffic) }} / {{ formatBytes(store.result?.subscription_info?.total) }}
          </span>
        </div>
      </div>

      <!-- 警告 -->
      <div v-if="store.result?.warnings?.length" class="px-3 py-2 border-b border-slate-100 shrink-0">
        <NAlert
          v-for="(warning, idx) in store.result.warnings"
          :key="idx"
          type="warning"
          class="text-xs mb-1 last:mb-0"
        >
          <template #icon>
            <NIcon size="14"><WarningOutline /></NIcon>
          </template>
          {{ warning }}
        </NAlert>
      </div>

      <!-- YAML 预览区 / 空状态 -->
      <div class="flex-1 min-h-0 overflow-hidden">
        <!-- 空状态 -->
        <div v-if="!store.result && !store.loading" class="flex flex-col items-center justify-center h-full text-slate-400">
          <div class="w-16 h-16 rounded-2xl bg-slate-100 flex items-center justify-center mb-4">
            <span class="i-carbon-document-blank w-8 h-8 text-slate-300"></span>
          </div>
          <p class="text-sm text-slate-500 mb-1">尚未生成配置</p>
          <p class="text-xs text-slate-400">在左侧输入订阅链接，点击"转换"按钮</p>
        </div>

        <!-- 加载状态 -->
        <div v-else-if="store.loading" class="flex flex-col items-center justify-center h-full gap-3">
          <div class="w-8 h-8 border-2 border-slate-200 border-t-indigo-500 rounded-full animate-spin"></div>
          <p class="text-sm text-slate-500">正在转换中...</p>
        </div>

        <!-- YAML 预览 -->
        <NScrollbar v-else class="h-full">
          <NCode
            :code="yamlPreview"
            language="yaml"
            word-wrap
            class="text-xs leading-relaxed p-3"
          />
        </NScrollbar>
      </div>
    </div>
  </div>
</template>

