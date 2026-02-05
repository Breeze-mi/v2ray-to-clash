import { defineStore } from 'pinia';
import { invoke } from '@tauri-apps/api/core';
import type { AppState, ConvertRequest, ConvertResult, PresetConfig, ParseNodesResult } from '../types';

export const useAppStore = defineStore('app', {
  state: (): AppState => ({
    subscription: '',
    selectedPreset: null,
    customIniUrl: '',
    includeRegex: '',
    excludeRegex: '',
    renamePattern: '',
    renameReplacement: '',
    enableTun: false,
    customUserAgent: '',
    loading: false,
    previewing: false,
    error: null,
    result: null,
    previewNodes: [],
    previewSubscriptionInfo: null,
    presets: [],
  }),

  getters: {
    hasSubscription: (state) => state.subscription.trim().length > 0,
    hasResult: (state) => state.result !== null,
    hasPreview: (state) => state.previewNodes.length > 0,
    effectiveIniUrl: (state) => {
      if (state.selectedPreset) {
        const preset = state.presets.find(p => p.name === state.selectedPreset);
        return preset?.url || '';
      }
      return state.customIniUrl;
    },
  },

  actions: {
    async loadPresets() {
      try {
        this.presets = await invoke<PresetConfig[]>('get_preset_configs');
      } catch (e) {
        this.error = String(e);
      }
    },

    async convert() {
      if (!this.hasSubscription) {
        this.error = '请输入订阅链接';
        return;
      }

      this.loading = true;
      this.error = null;
      this.result = null;
      this.previewNodes = [];

      try {
        const request: ConvertRequest = {
          subscription: this.subscription,
          ini_url: this.effectiveIniUrl || undefined,
          include_regex: this.includeRegex || undefined,
          exclude_regex: this.excludeRegex || undefined,
          rename_pattern: this.renamePattern || undefined,
          rename_replacement: this.renameReplacement || undefined,
          enable_tun: this.enableTun,
          custom_user_agent: this.customUserAgent || undefined,
          timeout_secs: 30,
        };

        this.result = await invoke<ConvertResult>('convert_subscription', { request });
      } catch (e) {
        this.error = String(e);
      } finally {
        this.loading = false;
      }
    },

    async validateRegex(pattern: string): Promise<boolean> {
      if (!pattern) return true;
      try {
        await invoke<boolean>('validate_regex', { pattern });
        return true;
      } catch {
        return false;
      }
    },

    async preview() {
      if (!this.hasSubscription) {
        this.error = '请输入订阅链接';
        return;
      }

      this.previewing = true;
      this.error = null;
      this.previewNodes = [];
      this.previewSubscriptionInfo = null;

      try {
        const result = await invoke<ParseNodesResult>('parse_nodes', {
          content: this.subscription,
          include_regex: this.includeRegex || null,
          exclude_regex: this.excludeRegex || null,
        });
        this.previewNodes = result.nodes;
        this.previewSubscriptionInfo = result.subscription_info || null;
      } catch (e) {
        this.error = String(e);
      } finally {
        this.previewing = false;
      }
    },

    clearResult() {
      this.result = null;
      this.error = null;
    },

    reset() {
      this.subscription = '';
      this.selectedPreset = null;
      this.customIniUrl = '';
      this.includeRegex = '';
      this.excludeRegex = '';
      this.renamePattern = '';
      this.renameReplacement = '';
      this.enableTun = false;
      this.customUserAgent = '';
      this.result = null;
      this.previewNodes = [];
      this.previewSubscriptionInfo = null;
      this.error = null;
    },
  },
});
