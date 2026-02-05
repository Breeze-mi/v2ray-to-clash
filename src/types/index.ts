// Types for LocalSub frontend

export interface ConvertRequest {
  subscription: string;
  ini_url?: string;
  ini_content?: string;
  include_regex?: string;
  exclude_regex?: string;
  rename_pattern?: string;
  rename_replacement?: string;
  timeout_secs?: number;
}

export interface ConvertResult {
  yaml: string;
  node_count: number;
  filtered_count: number;
  group_count: number;
  rule_count: number;
  warnings: string[];
}

export interface PresetConfig {
  name: string;
  url: string;
  description: string;
}

export interface AppState {
  // Input
  subscription: string;
  selectedPreset: string | null;
  customIniUrl: string;

  // Advanced options
  includeRegex: string;
  excludeRegex: string;
  renamePattern: string;
  renameReplacement: string;

  // State
  loading: boolean;
  error: string | null;

  // Output
  result: ConvertResult | null;
  presets: PresetConfig[];
}
