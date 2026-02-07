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
  enable_tun?: boolean;
  custom_user_agent?: string;
  enable_udp?: boolean;
  enable_tfo?: boolean;
  skip_cert_verify?: boolean;
  vless_reality_short_id_override?: string;
  api_listen_lan?: boolean;
  api_secret?: string;
  rule_provider_proxy?: string;
  rule_provider_header?: string;
  rule_provider_size_limit?: number;
  rule_provider_path_omit?: boolean;
  rule_provider_path_template?: string;
}

export interface SubscriptionInfo {
  upload?: number;
  download?: number;
  total?: number;
  expire?: number;
}

export interface ConvertResult {
  yaml: string;
  node_count: number;
  filtered_count: number;
  group_count: number;
  rule_count: number;
  warnings: string[];
  subscription_info?: SubscriptionInfo;
}

export interface PresetConfig {
  name: string;
  url: string;
  description: string;
}

export interface NodePreviewItem {
  name: string;
  protocol: string;
  server: string;
  port: number;
}

export interface ParseNodesResult {
  nodes: NodePreviewItem[];
  subscription_info?: SubscriptionInfo;
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
  enableTun: boolean;
  customUserAgent: string;
  enableUdp: boolean;
  enableTfo: boolean;
  skipCertVerify: boolean;
  vlessRealityShortIdOverride: string;
  apiListenLan: boolean;
  ruleProviderProxy: string;
  ruleProviderHeader: string;
  ruleProviderSizeLimit: number | null;
  ruleProviderPathOmit: boolean;
  ruleProviderPathTemplate: string;

  // State
  loading: boolean;
  previewing: boolean;
  error: string | null;

  // Output
  result: ConvertResult | null;
  previewNodes: NodePreviewItem[];
  previewSubscriptionInfo: SubscriptionInfo | null;
  presets: PresetConfig[];
}
