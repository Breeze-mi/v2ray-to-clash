import { defineStore } from 'pinia';
import { invoke } from '@tauri-apps/api/core';
import type { AppState, ConvertRequest, ConvertResult, PresetConfig } from '../types';

export const useAppStore = defineStore('app', {
  state: (): AppState => ({
    subscription: '',
    selectedPreset: null,
    customIniUrl: '',
    includeRegex: '',
    excludeRegex: '',
    renamePattern: '',
    renameReplacement: '',
    loading: false,
    error: null,
    result: null,
    presets: [],
  }),

  getters: {
    hasSubscription: (state) => state.subscription.trim().length > 0,
    hasResult: (state) => state.result !== null,
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
        console.error('Failed to load presets:', e);
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

      try {
        const request: ConvertRequest = {
          subscription: this.subscription,
          ini_url: this.effectiveIniUrl || undefined,
          include_regex: this.includeRegex || undefined,
          exclude_regex: this.excludeRegex || undefined,
          rename_pattern: this.renamePattern || undefined,
          rename_replacement: this.renameReplacement || undefined,
          timeout_secs: 30,
        };

        this.result = await invoke<ConvertResult>('convert_subscription', { request });

        if (this.result.warnings.length > 0) {
          console.warn('Conversion warnings:', this.result.warnings);
        }
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
      this.result = null;
      this.error = null;
    },
  },
});
