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
  type SelectOption,
} from 'naive-ui';
import { HelpCircleOutline, RefreshOutline } from '@vicons/ionicons5';
import { useAppStore } from '../stores/app';

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
  <div class="config-panel">
    <div class="section">
      <div class="section-header">
        <span class="section-title">订阅链接</span>
        <NTooltip>
          <template #trigger>
            <NIcon size="16" class="help-icon">
              <HelpCircleOutline />
            </NIcon>
          </template>
          支持订阅 URL 或直接粘贴节点链接，每行一个
        </NTooltip>
      </div>
      <NInput
        v-model:value="store.subscription"
        type="textarea"
        placeholder="输入订阅链接或节点内容...
支持格式:
- 订阅 URL (http/https)
- VLESS/VMess/SS/Trojan 链接
- Base64 编码内容"
        :rows="8"
        class="subscription-input"
      />
    </div>

    <div class="section">
      <div class="section-header">
        <span class="section-title">远程配置</span>
        <NTooltip>
          <template #trigger>
            <NIcon size="16" class="help-icon">
              <HelpCircleOutline />
            </NIcon>
          </template>
          选择 ACL4SSR 预设配置或输入自定义 INI 配置 URL
        </NTooltip>
      </div>
      <NSelect
        v-model:value="store.selectedPreset"
        :options="presetOptions"
        placeholder="选择预设配置..."
        clearable
        class="preset-select"
      />
      <NInput
        v-if="!store.selectedPreset"
        v-model:value="store.customIniUrl"
        placeholder="自定义 INI 配置 URL（可选）"
        class="custom-url-input"
      />
    </div>

    <NCollapse>
      <NCollapseItem title="高级选项" name="advanced">
        <div class="advanced-options">
          <div class="option-group">
            <div class="option-header">
              <span>节点筛选</span>
              <NTooltip>
                <template #trigger>
                  <NIcon size="14" class="help-icon">
                    <HelpCircleOutline />
                  </NIcon>
                </template>
                使用正则表达式筛选节点，支持 | 分隔多个条件
              </NTooltip>
            </div>
            <NSpace vertical>
              <NInput
                v-model:value="store.includeRegex"
                placeholder="包含节点（正则）如: HK|香港|US|美国"
                :status="includeError ? 'error' : undefined"
                @blur="validateIncludeRegex"
              />
              <NInput
                v-model:value="store.excludeRegex"
                placeholder="排除节点（正则）如: 官网|到期|剩余"
                :status="excludeError ? 'error' : undefined"
                @blur="validateExcludeRegex"
              />
            </NSpace>
          </div>

          <div class="option-group">
            <div class="option-header">
              <span>节点重命名</span>
              <NTooltip>
                <template #trigger>
                  <NIcon size="14" class="help-icon">
                    <HelpCircleOutline />
                  </NIcon>
                </template>
                使用正则表达式查找替换节点名称
              </NTooltip>
            </div>
            <NSpace vertical>
              <NInput
                v-model:value="store.renamePattern"
                placeholder="查找（正则）如: \[.+\]"
                :status="renameError ? 'error' : undefined"
                @blur="validateRenameRegex"
              />
              <NInput
                v-model:value="store.renameReplacement"
                placeholder="替换为（留空删除）"
              />
            </NSpace>
          </div>
        </div>
      </NCollapseItem>
    </NCollapse>

    <div class="actions">
      <NButton
        type="primary"
        size="large"
        :loading="store.loading"
        :disabled="!store.hasSubscription"
        @click="store.convert"
      >
        <template #icon>
          <NIcon>
            <RefreshOutline />
          </NIcon>
        </template>
        转换订阅
      </NButton>
      <NButton
        size="large"
        :disabled="store.loading"
        @click="store.reset"
      >
        重置
      </NButton>
    </div>
  </div>
</template>

<style scoped>
.config-panel {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 6px;
}

.section-title {
  font-weight: 600;
  font-size: 14px;
  color: var(--text-color-1);
}

.help-icon {
  color: var(--text-color-3);
  cursor: help;
}

.subscription-input {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 13px;
}

.preset-select {
  width: 100%;
}

.custom-url-input {
  margin-top: 8px;
}

.advanced-options {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 8px 0;
}

.option-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.option-header {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: var(--text-color-2);
}

.actions {
  display: flex;
  gap: 12px;
  padding-top: 8px;
}
</style>
