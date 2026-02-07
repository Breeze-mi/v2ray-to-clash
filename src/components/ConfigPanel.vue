<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  NInput,
  NButton,
  NSelect,
  NCollapse,
  NCollapseItem,
  NSpace,
  NTooltip,
  NIcon,
  NSwitch,
  NProgress,
  type SelectOption,
} from 'naive-ui';
import { RefreshOutline, EyeOutline } from '@vicons/ionicons5';
import { useAppStore } from '../stores/app';
import { formatBytes, formatExpire } from '../utils/format';

const store = useAppStore();

const presetOptions = computed<SelectOption[]>(() => [
  { label: '自定义配置', value: '' },
  ...store.presets.map(p => ({
    label: `${p.name} - ${p.description}`,
    value: p.name,
  })),
]);

const includeError = ref<string | null>(null);
const excludeError = ref<string | null>(null);
const renameError = ref<string | null>(null);

const subInfo = computed(() => {
  const info = store.previewSubscriptionInfo;
  if (!info) return null;

  const used = (info.upload || 0) + (info.download || 0);
  const total = info.total || 0;
  const percentage = total > 0 ? Math.round((used / total) * 100) : 0;

  return {
    used: info.upload !== undefined && info.download !== undefined ? formatBytes(used) : '-',
    total: info.total !== undefined ? formatBytes(total) : '-',
    upload: info.upload !== undefined ? formatBytes(info.upload) : '-',
    download: info.download !== undefined ? formatBytes(info.download) : '-',
    expire: info.expire !== undefined ? formatExpire(info.expire) : '-',
    percentage,
  };
});

async function validateIncludeRegex() {
  if (!store.includeRegex) {
    includeError.value = null;
    return;
  }
  const valid = await store.validateRegex(store.includeRegex);
  includeError.value = valid ? null : '无效的正则表达式';
}

async function validateExcludeRegex() {
  if (!store.excludeRegex) {
    excludeError.value = null;
    return;
  }
  const valid = await store.validateRegex(store.excludeRegex);
  excludeError.value = valid ? null : '无效的正则表达式';
}

async function validateRenameRegex() {
  if (!store.renamePattern) {
    renameError.value = null;
    return;
  }
  const valid = await store.validateRegex(store.renamePattern);
  renameError.value = valid ? null : '无效的正则表达式';
}
</script>

<template>
  <div class="flex flex-col gap-4">
    <!-- 订阅链接 -->
    <div class="flex flex-col gap-2">
      <div class="flex items-center gap-1">
        <span class="text-xs font-semibold text-slate-600">订阅链接</span>
        <NTooltip>
          <template #trigger>
            <span class="i-carbon-help text-slate-400 w-3.5 h-3.5 cursor-help"></span>
          </template>
          支持订阅 URL 或直接粘贴节点链接，每行一个
        </NTooltip>
      </div>
      <NInput
        v-model:value="store.subscription"
        type="textarea"
        placeholder="输入订阅链接或节点内容...
支持: 订阅URL、VLESS/VMess/SS/SSR/Trojan/Hysteria/TUIC链接、Base64"
        :rows="4"
        size="small"
        class="font-mono text-xs"
      />
    </div>

    <!-- 远程配置 -->
    <div class="flex flex-col gap-2">
      <div class="flex items-center gap-1">
        <span class="text-xs font-semibold text-slate-600">远程配置</span>
        <NTooltip>
          <template #trigger>
            <span class="i-carbon-help text-slate-400 w-3.5 h-3.5 cursor-help"></span>
          </template>
          选择 ACL4SSR 预设配置或输入自定义 INI 配置 URL
        </NTooltip>
      </div>
      <NSelect
        v-model:value="store.selectedPreset"
        :options="presetOptions"
        placeholder="选择预设配置..."
        clearable
        size="small"
      />
      <NInput
        v-if="!store.selectedPreset"
        v-model:value="store.customIniUrl"
        placeholder="自定义 INI 配置 URL（可选）"
        size="small"
      />
    </div>

    <!-- 高级选项 -->
    <NCollapse>
      <NCollapseItem title="高级选项" name="advanced">
        <div class="flex flex-col gap-4 py-1">
          <!-- 节点筛选 -->
          <div class="flex flex-col gap-2">
            <div class="flex items-center gap-1">
              <span class="text-xs text-slate-500">节点筛选</span>
              <NTooltip>
                <template #trigger>
                  <span class="i-carbon-help text-slate-400 w-3 h-3 cursor-help"></span>
                </template>
                使用正则表达式筛选节点，支持 | 分隔多个条件
              </NTooltip>
            </div>
            <NSpace vertical size="small">
              <NInput
                v-model:value="store.includeRegex"
                placeholder="包含节点（正则）如: HK|香港|US|美国"
                size="small"
                :status="includeError ? 'error' : undefined"
                @blur="validateIncludeRegex"
              />
              <NInput
                v-model:value="store.excludeRegex"
                placeholder="排除节点（正则）如: 官网|到期|剩余"
                size="small"
                :status="excludeError ? 'error' : undefined"
                @blur="validateExcludeRegex"
              />
            </NSpace>
          </div>

          <!-- 节点重命名 -->
          <div class="flex flex-col gap-2">
            <div class="flex items-center gap-1">
              <span class="text-xs text-slate-500">节点重命名</span>
              <NTooltip>
                <template #trigger>
                  <span class="i-carbon-help text-slate-400 w-3 h-3 cursor-help"></span>
                </template>
                使用正则表达式查找替换节点名称
              </NTooltip>
            </div>
            <NSpace vertical size="small">
              <NInput
                v-model:value="store.renamePattern"
                placeholder="查找（正则）如: \[.+\]"
                size="small"
                :status="renameError ? 'error' : undefined"
                @blur="validateRenameRegex"
              />
              <NInput
                v-model:value="store.renameReplacement"
                placeholder="替换为（留空删除）"
                size="small"
              />
            </NSpace>
          </div>

          <!-- 输出选项 -->
          <div class="flex flex-col gap-2">
            <span class="text-xs text-slate-500">输出选项</span>
            <div class="flex flex-col gap-1 bg-slate-50 rounded-md p-2">
              <div class="flex justify-between items-center py-1">
                <span class="text-xs text-slate-600">TUN 模式（系统代理）</span>
                <NSwitch v-model:value="store.enableTun" size="small" />
              </div>
              <div class="flex justify-between items-center py-1">
                <span class="text-xs text-slate-600">启用 UDP</span>
                <NSwitch v-model:value="store.enableUdp" size="small" />
              </div>
              <div class="flex justify-between items-center py-1">
                <span class="text-xs text-slate-600">TCP Fast Open</span>
                <NSwitch v-model:value="store.enableTfo" size="small" />
              </div>
              <div class="flex justify-between items-center py-1">
                <span class="text-xs text-slate-600">跳过证书验证</span>
                <NSwitch v-model:value="store.skipCertVerify" size="small" />
              </div>
              <div class="flex justify-between items-center py-1">
                <div class="flex items-center gap-1">
                  <span class="text-xs text-slate-600">允许局域网控制 API</span>
                  <NTooltip>
                    <template #trigger>
                      <span class="i-carbon-help text-slate-400 w-3 h-3 cursor-help"></span>
                    </template>
                   
                  </NTooltip>
                </div>
                <NSwitch v-model:value="store.apiListenLan" size="small" />
              </div>
            </div>
          </div>

          <!-- 自定义 UA -->
          <div class="flex flex-col gap-2">
            <div class="flex items-center gap-1">
              <span class="text-xs text-slate-500">自定义 User-Agent</span>
              <NTooltip>
                <template #trigger>
                  <span class="i-carbon-help text-slate-400 w-3 h-3 cursor-help"></span>
                </template>
                某些机场检查 UA，可自定义抓取订阅时的 User-Agent
              </NTooltip>
            </div>
            <NInput
              v-model:value="store.customUserAgent"
              placeholder="默认: clash-verge/v2.0.0"
              size="small"
            />
          </div>

          <!-- API Secret -->
          <div class="flex flex-col gap-2">
            <div class="flex items-center gap-1">
              <span class="text-xs text-slate-500">API Secret（可选）</span>
              <NTooltip>
                <template #trigger>
                  <span class="i-carbon-help text-slate-400 w-3 h-3 cursor-help"></span>
                </template>
              </NTooltip>
            </div>
            <NInput
              v-model:value="store.apiSecret"
              placeholder="建议设置一个随机字符串"
              size="small"
            />
          </div>
        </div>
      </NCollapseItem>
    </NCollapse>

    <!-- 操作按钮 -->
    <div class="flex gap-2 pt-1">
      <NButton
        type="primary"
        size="small"
        :loading="store.loading"
        :disabled="!store.hasSubscription"
        class="flex-1"
        @click="store.convert"
      >
        <template #icon>
          <NIcon><RefreshOutline /></NIcon>
        </template>
        转换
      </NButton>
      <NButton
        size="small"
        :loading="store.previewing"
        :disabled="!store.hasSubscription || store.loading"
        @click="store.preview"
      >
        <template #icon>
          <NIcon><EyeOutline /></NIcon>
        </template>
        预览
      </NButton>
      <NButton
        size="small"
        :disabled="store.loading"
        @click="store.reset"
      >
        重置
      </NButton>
    </div>

    <!-- 节点预览 -->
    <div v-if="store.hasPreview" class="flex flex-col gap-3 mt-1">
      <!-- 订阅信息 -->
      <div v-if="subInfo" class="bg-gradient-to-br from-emerald-50 to-green-50 border border-emerald-200 rounded-lg p-3">
        <div class="flex justify-between items-center mb-2">
          <span class="text-xs font-semibold text-emerald-700 flex items-center gap-1">
            <span class="i-carbon-cloud-download w-3.5 h-3.5"></span>
            订阅信息
          </span>
          <span class="text-xs text-slate-500">到期: {{ subInfo.expire }}</span>
        </div>
        <div class="flex flex-col gap-1">
          <div class="flex justify-between text-xs text-slate-600">
            <span>已用: {{ subInfo.used }}</span>
            <span>总量: {{ subInfo.total }}</span>
          </div>
          <NProgress
            type="line"
            :percentage="subInfo.percentage"
            :indicator-placement="'inside'"
            :height="18"
            :border-radius="4"
            :status="subInfo.percentage > 90 ? 'error' : subInfo.percentage > 70 ? 'warning' : 'success'"
          />
          <div class="flex justify-between text-xs text-slate-400">
            <span>上传: {{ subInfo.upload }}</span>
            <span>下载: {{ subInfo.download }}</span>
          </div>
        </div>
      </div>

      <!-- 节点列表 -->
      <div>
        <div class="flex justify-between items-center mb-2">
          <span class="text-xs font-semibold text-slate-600 flex items-center gap-1">
            <span class="i-carbon-network-3 w-3.5 h-3.5"></span>
            节点预览
          </span>
          <span class="text-xs text-slate-400">{{ store.previewNodes.length }} 个节点</span>
        </div>
        <div class="max-h-40 overflow-y-auto border border-slate-200 rounded-lg bg-white">
          <div
            v-for="(node, idx) in store.previewNodes"
            :key="idx"
            class="flex items-center gap-2 px-2.5 py-1.5 text-xs border-b border-slate-100 last:border-b-0 hover:bg-slate-50 transition-colors"
          >
            <span
              class="px-1.5 py-0.5 rounded text-white text-xs font-semibold min-w-12 text-center shrink-0"
              :class="{
                'bg-indigo-500': node.protocol.toLowerCase() === 'vless',
                'bg-violet-500': node.protocol.toLowerCase() === 'vmess',
                'bg-emerald-500': node.protocol.toLowerCase() === 'ss',
                'bg-green-400': node.protocol.toLowerCase() === 'ssr',
                'bg-red-500': node.protocol.toLowerCase() === 'trojan',
                'bg-amber-500': node.protocol.toLowerCase() === 'hysteria',
                'bg-orange-500': node.protocol.toLowerCase() === 'hysteria2',
                'bg-teal-500': node.protocol.toLowerCase() === 'tuic',
                'bg-purple-500': node.protocol.toLowerCase() === 'wireguard',
                'bg-slate-400': !['vless', 'vmess', 'ss', 'ssr', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'wireguard'].includes(node.protocol.toLowerCase()),
              }"
            >
              {{ node.protocol }}
            </span>
            <span class="flex-1 truncate text-slate-700">{{ node.name }}</span>
            <span class="text-xs text-slate-400 font-mono shrink-0">{{ node.server }}:{{ node.port }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
