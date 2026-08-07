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
  stats_key?: string;
  password?: string;
  subscription_token?: string;
  enabled: boolean;
  traffic_limit?: number;
  expiry_at?: number;
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
  config_changed?: boolean;
  changed_cores?: string[];
  auto_apply?: Record<string, CoreApplyJobStatus>;
  auto_apply_error?: Record<string, { error?: string; detail?: string }>;
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
  pending_apply?: boolean;
  pending_apply_error?: string;
  pending_apply_detail?: string;
  applied_config_hash?: string;
  generated_hash?: string;
  last_applied_at?: string;
  pending_reason?: string;
  pending_updated_at?: string;
  apply_job?: CoreApplyJobStatus;
}

export interface CoreApplyJobStatus {
  id: string;
  core: string;
  status: 'queued' | 'running' | 'retrying' | 'succeeded' | 'failed' | string;
  started_at?: string;
  finished_at?: string;
  message?: string;
  error?: string;
  detail?: string;
  accepted?: boolean;
  retry_count?: number;
  max_retries?: number;
  next_retry_at?: string;
}

export interface CoreActionResponse {
  core?: string;
  status?: string;
  accepted?: boolean;
  message?: string;
  output?: string;
  commands_executed?: string[];
  apply_job?: CoreApplyJobStatus;
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
    pending_apply?: boolean;
    pending_apply_error?: string;
    pending_apply_detail?: string;
    applied_config_hash?: string;
    generated_hash?: string;
    last_applied_at?: string;
    pending_reason?: string;
    pending_updated_at?: string;
  };
  singbox?: {
    status?: string;
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
    pending_apply?: boolean;
    pending_apply_error?: string;
    pending_apply_detail?: string;
    applied_config_hash?: string;
    generated_hash?: string;
    last_applied_at?: string;
    pending_reason?: string;
    pending_updated_at?: string;
  };
  applied?: boolean;
  pending_apply?: boolean;
  pending_apply_error?: string;
  pending_apply_detail?: string;
  pending_cores?: string[];
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
  pending_apply?: boolean;
  error?: string;
  detail?: string;
  applied_config_hash?: string;
  last_applied_at?: string;
  pending_reason?: string;
  pending_updated_at?: string;
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

export interface TrafficCumulative {
  up: number;
  down: number;
  total: number;
  status?: string;
  source?: string;
  message?: string;
}

export interface TrafficRealtime {
  delta_up: number;
  delta_down: number;
  delta_total: number;
  rate_up: number;
  rate_down: number;
  rate_total: number;
  window_seconds?: number;
  observed_at?: string;
  status?: string;
  source?: string;
  message?: string;
  coverage?: TrafficCoverage;
}

export interface TrafficV2Coverage {
  overall: string;
  engines: Record<string, string>;
  ok: number;
  waiting: number;
  stale: number;
  unavailable: number;
  unsupported: number;
  partial: number;
  not_configured?: number;
}

export interface TrafficV2Metric {
  up: number;
  down: number;
  total: number;
  status: string;
  source: string;
  message: string;
}

export interface TrafficV2Realtime {
  delta_up: number;
  delta_down: number;
  delta_total: number;
  rate_up: number;
  rate_down: number;
  rate_total: number;
  observed_at: string;
  window_seconds: number;
  status: string;
  source: string;
  message: string;
}

export interface TrafficV2Total {
  cumulative: TrafficV2Metric;
  realtime: TrafficV2Realtime;
}

export interface TrafficV2Inbound {
  id: number;
  remark: string;
  protocol: string;
  port: number;
  enabled: boolean;
  cumulative: TrafficV2Metric;
  realtime: TrafficV2Realtime;
}

export interface TrafficV2Client {
  id: number;
  inbound_id: number;
  email: string;
  enabled: boolean;
  traffic_limit: number;
  expiry_at: number;
  cumulative: TrafficV2Metric;
  realtime: TrafficV2Realtime;
}

export interface TrafficV2Snapshot {
  generated_at: string;
  observed_at: string;
  window_seconds: number;
  total: TrafficV2Total;
  inbounds: TrafficV2Inbound[];
  clients: TrafficV2Client[];
  coverage: TrafficV2Coverage;
}

export interface TrafficV2Patch {
  generated_at: string;
  observed_at: string;
  window_seconds: number;
  total?: TrafficV2Total;
  inbounds?: TrafficV2Inbound[];
  removed_inbound_ids?: number[];
  clients?: TrafficV2Client[];
  removed_client_ids?: number[];
  coverage?: TrafficV2Coverage;
}

export interface TrafficV2AnalyticsPoint {
  time: string;
  up: number;
  down: number;
  total: number;
  rate_up: number;
  rate_down: number;
  rate_total: number;
}

export interface TrafficV2AnalyticsSummary {
  up: number;
  down: number;
  total: number;
  rate_up: number;
  rate_down: number;
  rate_total: number;
  peak_up: number;
  peak_down: number;
  peak_total: number;
  peak_rate: number;
  peak_at?: string;
  points: number;
  has_data: boolean;
  empty_reason?: string;
}

export interface TrafficV2AnalyticsRank {
  id: number;
  label: string;
  scope_key?: string;
  protocol?: string;
  up: number;
  down: number;
  total: number;
  rate_total?: number;
}

export interface TrafficV2HeatmapPoint {
  day: string;
  hour: number;
  total: number;
  rate_total?: number;
}

export interface TrafficV2AnalyticsResponse {
  generated_at: string;
  range: '1h' | '24h' | '7d' | '30d' | string;
  metric: 'usage' | 'rate' | 'cumulative' | string;
  scope_type: 'inbound' | 'client' | string;
  semantics?: string;
  bucket_seconds: number;
  summary: TrafficV2AnalyticsSummary;
  series: TrafficV2AnalyticsPoint[];
  top_clients: TrafficV2AnalyticsRank[];
  top_inbounds: TrafficV2AnalyticsRank[];
  heatmap?: TrafficV2HeatmapPoint[];
}

export interface VersionResponse {
  version: string;
}

export interface Settings {
  panel_port?: number;
  panel_username?: string;
  panel_password?: string;
  web_base_path?: string;
  public_host?: string;
  trust_proxy?: boolean;
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
