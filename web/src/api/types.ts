export interface Session {
  auth_enabled: boolean;
  authenticated: boolean;
  username: string;
  revoked: boolean;
  default_password: boolean;
}

export interface Client {
  id: number;
  inbound_id: number;
  email: string;
  uuid: string;
  credential_id?: string;
  password?: string;
  subscription_token?: string;
  enabled: boolean;
  up?: number;
  down?: number;
  traffic_limit?: number;
  expiry_at?: number;
  xray_up?: number;
  xray_down?: number;
  rate_up?: number;
  rate_down?: number;
  traffic_status?: string;
  traffic_message?: string;
  traffic_stats_source?: string;
  realtime_stats_source?: string;
  traffic_stats_note?: string;
}

export interface Inbound {
  id: number;
  remark: string;
  protocol: string;
  core?: 'xray' | 'sing-box' | string;
  port: number;
  network: string;
  security: string;
  enabled: boolean;
  uuid?: string;
  clients?: Client[];
  traffic_up?: number;
  traffic_down?: number;
  traffic_total?: number;
  rate_up?: number;
  rate_down?: number;
  traffic_status?: string;
  traffic_message?: string;
  traffic_stats_source?: string;
  realtime_stats_source?: string;
  client_traffic?: Record<string, { up: number; down: number; rate_up?: number; rate_down?: number; xray_up?: number; xray_down?: number; status?: string; message?: string; source?: string; realtime_source?: string; note?: string }>;
  [key: string]: unknown;
}

export interface SingboxApplySummary {
  applied?: boolean;
  service?: string;
  config_path?: string;
  commands_executed?: string[];
  error?: string;
  reason?: string;
  detail?: string;
  output?: string;
  warnings?: string[];
  post_apply_warnings?: string[];
  non_fatal_warnings?: string[];
  inbounds?: number;
  outbounds?: number;
  rules?: number;
}

export interface XrayApplySummary {
  applied?: boolean;
  status?: string;
  service?: string;
  config_path?: string;
  commands_executed?: string[];
  error?: string;
  detail?: string;
  warnings?: string[];
  post_apply_warnings?: string[];
  error_output?: string;
  inbounds?: number;
  outbounds?: number;
  rules?: number;
}

export interface CoreDiagnosticAction {
  code: string;
  severity: 'error' | 'warning' | 'info' | string;
  category: 'service' | 'config' | 'listener' | 'log' | 'security' | 'routing' | string;
  message: string;
  command?: string;
  inbound_id?: number;
  port?: number;
}

export interface CreateResultFields {
  created?: boolean;
  applied?: boolean;
  error?: string;
  detail?: string;
  warnings?: string[];
  post_apply_warnings?: string[];
  non_fatal_warnings?: string[];
  singbox?: SingboxApplySummary;
  xray?: XrayApplySummary;
}

export type CreateInboundResponse = (Inbound | { inbound: Inbound }) & CreateResultFields;
export type CreateClientResponse = (Client | { client: Client }) & CreateResultFields;

export interface InboundCapability {
  protocol: string;
  core: 'xray' | 'sing-box' | string;
  template_id?: string;
  template_label?: string;
  template_summary?: string;
  networks: string[];
  securities: string[];
  default_network: string;
  default_security: string;
  security_by_network: Record<string, string[]>;
  visible_fields?: string[];
  auto_generate_fields?: string[];
  expert_fields?: string[];
  advanced_fields?: string[];
  credential_type: 'none' | 'uuid' | 'password' | 'credential_id_password' | 'username_password' | string;
  subscription: 'none' | 'full' | string;
  share_link?: boolean;
  local_proxy_inbound?: boolean;
  unsupported_reasons?: string[];
}

export interface Outbound {
  id: number;
  tag: string;
  remark?: string;
  protocol: string;
  address?: string;
  port?: number;
  username?: string;
  password?: string;
  supported_cores?: Array<'xray' | 'sing-box' | string>;
  enabled: boolean;
  sort?: number;
  source?: 'manual' | 'subscription' | 'proxy_pool' | string;
  subscription_id?: number;
  subscription_identity?: string;
  raw_link?: string;
  settings_json?: string;
  last_seen_at?: string;
  [key: string]: unknown;
}

export interface OutboundSubscription {
  id: number;
  remark: string;
  url: string;
  tag_prefix: string;
  update_interval_seconds: number;
  enabled: boolean;
  allow_private: boolean;
  prepend: boolean;
  priority: number;
  last_fetched_at?: string;
  last_attempt_at?: string;
  last_error?: string;
  link_identities_json?: string;
  outbound_count?: number;
  created_at?: string;
  updated_at?: string;
}

export interface OutboundSubscriptionSkippedEntry {
  raw: string;
  reason: string;
  protocol?: string;
}

export interface OutboundSubscriptionPreview {
  nodes: Array<Record<string, unknown>>;
  count: number;
  skipped_count: number;
  skipped: OutboundSubscriptionSkippedEntry[];
}

export interface RoutingRule {
  id: number;
  remark?: string;
  inbound_id?: number;
  inbound_tag?: string;
  client_id?: number;
  client_email?: string;
  client_label?: string;
  domain?: string;
  ip?: string;
  rule_set?: string;
  protocol?: string;
  outbound_id?: number;
  outbound_tag: string;
  enabled: boolean;
  sort_order?: number;
  [key: string]: unknown;
}

export interface Resources {
  cpu_percent: number;
  memory_total: number;
  memory_used: number;
  memory_percent: number;
  disk_total: number;
  disk_used: number;
  disk_percent: number;
  uptime_seconds: number;
}

export interface CoreStatus {
  core?: string;
  service: string;
  status: string;
  service_status?: string;
  managed?: boolean;
  installed?: boolean;
  version?: string;
  binary_path?: string;
  binary_version?: string;
  config_exists?: boolean;
  config_valid?: boolean;
  config_error?: string;
  memory_rss_bytes?: number;
  uptime?: string;
  active_connections?: number;
  config_path?: string;
  commands_executed?: string[];
  listening_ports?: CoreListenerDiagnostic[];
}

export interface CoreActionResponse {
  core?: string;
  status?: string;
  output?: string;
  commands_executed?: string[];
  xray?: {
    status?: string;
    service?: string;
    applied?: boolean;
    config_path?: string;
    commands_executed?: string[];
    error?: string;
    detail?: string;
    warnings?: string[];
    post_apply_warnings?: string[];
    error_output?: string;
    inbounds?: number;
    outbounds?: number;
    rules?: number;
  };
  singbox?: {
    applied?: boolean;
    service?: string;
    config_path?: string;
    reason?: string;
    error?: string;
    detail?: string;
    output?: string;
    commands_executed?: string[];
    warnings?: string[];
    post_apply_warnings?: string[];
    non_fatal_warnings?: string[];
    inbounds?: number;
    outbounds?: number;
    rules?: number;
  };
  applied?: boolean;
  reason?: string;
  error?: string;
  warnings?: string[];
  post_apply_warnings?: string[];
  non_fatal_warnings?: string[];
  inbounds?: number;
  outbounds?: number;
  rules?: number;
}

export interface SingboxWriteResponse {
  applied?: boolean;
  error?: string;
  detail?: string;
  warnings?: string[];
  post_apply_warnings?: string[];
  non_fatal_warnings?: string[];
  singbox?: SingboxApplySummary;
  xray?: XrayApplySummary;
}

export interface CoreListenerDiagnostic {
  inbound_id: number;
  protocol: string;
  port: number;
  network?: string;
  transport?: string;
  path?: string;
  grpc_service_name?: string;
  security?: string;
  listening: boolean;
}

export type SingboxListenerDiagnostic = CoreListenerDiagnostic;

export interface CoreConfigPreview {
  config_path: string;
  in_sync: boolean;
  reason?: 'disk_missing' | 'generated_build_failed' | 'hash_mismatch' | 'disk_parse_failed' | string;
  disk: {
    config_path: string;
    hash?: string;
    config?: unknown;
    error?: string;
    detail?: string;
  };
  generated: {
    config_path: string;
    hash?: string;
    config?: unknown;
    error?: string;
    detail?: string;
    warnings?: string[];
    inbounds?: number;
    outbounds?: number;
    rules?: number;
  };
}

export type SingboxConfigPreview = CoreConfigPreview;
export type XrayConfigPreview = CoreConfigPreview;

export interface CoreDiagnostics {
  installed: boolean;
  version?: string;
  managed: boolean;
  service: string;
  service_status: 'running' | 'stopped' | 'not_managed' | 'not_installed' | string;
  config_path: string;
  config_exists: boolean;
  config_valid: boolean;
  config_error?: string;
  disk_generated_in_sync: boolean;
  sync_reason?: string;
  expected_listeners: CoreListenerDiagnostic[];
  missing_listeners: CoreListenerDiagnostic[];
  recent_logs: string[];
  warnings: string[];
  suggestions: string[];
  actions?: CoreDiagnosticAction[];
  suggestion_details?: CoreDiagnosticAction[];
}

export type SingboxDiagnostics = CoreDiagnostics;
export type XrayDiagnostics = CoreDiagnostics;

export interface ConfigValidation {
  target: 'xray' | 'singbox';
  valid: boolean;
  error?: string;
  warnings?: string[];
  inbounds?: number;
  outbounds?: number;
  rules?: number;
}

export interface DashboardSummary {
  generated_at: string;
  counts: {
    inbounds: number;
    inbounds_enabled: number;
    clients: number;
    clients_active: number;
    clients_expired: number;
    clients_limited: number;
    outbounds: number;
    outbounds_enabled: number;
    routing_rules: number;
    routing_enabled: number;
  };
  protocols: Record<string, number>;
  validation: {
    xray: ConfigValidation;
    singbox: ConfigValidation;
  };
}

export interface ProxyPoolQuery {
  country?: string;
  summary?: boolean;
  page?: number;
  per_page?: number;
}

export interface TrafficCoverage {
  overall: string;
  ok?: number;
  partial?: number;
  unsupported?: number;
  not_configured?: number;
  unavailable?: number;
  stale?: number;
  waiting?: number;
  engines?: Record<string, string>;
}

export interface TrafficSummary {
  total_up: number;
  total_down: number;
  total: number;
  rate_up: number;
  rate_down: number;
  rate_total: number;
  status: TrafficCoverage;
  engine?: string;
  source?: string;
  last_sampled_at?: string;
  generated_at: string;
}

export interface TrafficInbound {
  id: number;
  remark: string;
  protocol: string;
  port: number;
  total_up: number;
  total_down: number;
  total: number;
  rate_up: number;
  rate_down: number;
  status: string;
  message?: string;
  engine?: string;
  source?: string;
  last_sampled_at?: string;
}

export interface TrafficClient {
  id: number;
  inbound_id: number;
  email: string;
  protocol: string;
  total_up: number;
  total_down: number;
  total: number;
  rate_up: number;
  rate_down: number;
  traffic_limit: number;
  expiry_at: number;
  status: string;
  message?: string;
  engine?: string;
  source?: string;
  last_sampled_at?: string;
}

export interface TrafficSeriesPoint {
  name: string;
  time?: string;
  up: number;
  down: number;
  rate_up?: number;
  rate_down?: number;
}

export interface VersionResponse {
  version: string;
}

export interface Settings {
  panel_port?: number;
  panel_username?: string;
  panel_password?: string;
  web_base_path?: string;
  database_path?: string;
  cert_domain?: string;
  cert_email?: string;
  has_password?: boolean;
  management_direct_enabled?: boolean;
  management_direct_auto_detect?: boolean;
  management_direct_hosts?: string[] | string;
  management_direct_ports?: number[] | string;
  [key: string]: unknown;
}

export interface UpdateCheck {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  release_url: string;
  release_name?: string;
  status: string;
  message?: string;
}

export interface UpdateStatus {
  status: string;
  current_version?: string;
  target_version?: string;
  message?: string;
  health_check?: string;
  rolled_back?: boolean;
  rollback_status?: string;
  started_at?: string;
  updated_at?: string;
}

export interface VersionInfo {
  version: string;
}

export interface SessionInfo {
  id: number;
  id_prefix: string;
  created_at: string;
  last_used: string;
  expires_at: string;
}

export interface CertificateOperation {
  id: number;
  certificate_id?: number;
  type: string;
  status: string;
  code?: string;
  message?: string;
  detail?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ManagedCertificate {
  id: number;
  name: string;
  source: 'acme' | 'import' | string;
  status: 'issued' | 'pending' | 'failed' | 'expired' | 'expiring_soon' | string;
  domains: string[];
  cert_path: string;
  key_path: string;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
  serial?: string;
  issue_email?: string;
  acme_directory_url?: string;
  challenge_method?: string;
  last_error?: string;
  usage_count: number;
  usages?: Inbound[];
}

export interface CertificatePreflightCheck {
  code: string;
  status: 'ok' | 'warning' | 'failed' | string;
  message?: string;
  detail?: string;
}

export interface CertificatePreflight {
  ok: boolean;
  checks: CertificatePreflightCheck[];
}

export interface CertificateApplyResponse {
  status?: string;
  inbounds?: Inbound[];
  warnings?: string[];
  xray?: XrayApplySummary;
  singbox?: SingboxApplySummary;
  applied?: boolean;
  error?: string;
  detail?: string;
}

export interface CertStatus {
  domain: string;
  email: string;
  issued: boolean;
  cert_path: string;
  key_path: string;
}

export interface ProxyPoolRegion {
  code: string;
  name: string;
  count: number;
}

export interface ProxyPoolProxy {
  protocol?: string;
  address: string;
  port: number;
  username?: string;
  password?: string;
  country_code: string;
  country: string;
  city: string;
  asn: string;
  organization: string;
  latitude?: number;
  longitude?: number;
  latency?: number;
}

export interface ProxyPoolResponse {
  regions: ProxyPoolRegion[];
  proxies: ProxyPoolProxy[];
  total?: number;
  page?: number;
  per_page?: number;
  cache_status: string;
  cache_updated_at: string;
  next_refresh_at: string;
}

export type Socks5PoolRegion = ProxyPoolRegion;
export type Socks5PoolProxy = ProxyPoolProxy;
export type Socks5PoolResponse = ProxyPoolResponse;

export interface PingResult {
  latency: number;
  method?: string;
  error?: string;
}
