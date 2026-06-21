import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Columns2, Copy, Edit2, Plus, Power, QrCode, RectangleHorizontal, RotateCcw, Trash2 } from 'lucide-react';
import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import type { CertStatus, Client, Inbound, InboundCapability as ApiInboundCapability } from '../api/types';
import { EmptyState, LoadingBlock, Modal, SpinnerButton, StatusBadge, toggleButtonClass, useConfirm, useToast } from '../components/ui';
import { copyToClipboard } from '../lib/clipboard';
import { inboundCore } from '../lib/cores';
import { formatBytes, randomUUID } from '../lib/format';
import { useI18n } from '../lib/i18n';
import { showCoreApplyWarning } from '../lib/coreApply';
import { refreshTopologyDependencies } from '../lib/queryInvalidation';
import { usePageVisible } from '../lib/visibility';
import { PageTitle } from './OverviewPage';
import type { ClientValues, InboundValues } from './InboundsPageForms';
import QRCode from 'qrcode';

const InboundModal = lazy(() => import('./InboundsPageForms').then((module) => ({ default: module.InboundModal })));
const ClientModal = lazy(() => import('./InboundsPageForms').then((module) => ({ default: module.ClientModal })));

export const advancedFields = [
  'ws_path',
  'ws_host',
  'grpc_service_name',
  'reality_dest',
  'reality_server_names',
  'reality_short_id',
  'reality_private_key',
  'reality_public_key',
  'ss_method',
  'tls_cert_file',
  'tls_key_file',
  'tls_sni',
  'tls_fingerprint',
  'tls_alpn',
  'xhttp_path',
  'xhttp_mode',
  'hy2_up_mbps',
  'hy2_down_mbps',
  'hy2_obfs',
  'hy2_obfs_password',
  'hy2_mport',
  'tuic_congestion_control',
  'tuic_zero_rtt',
  'shadowtls_version',
  'shadowtls_password',
] as const;

export type InboundAdvancedField = (typeof advancedFields)[number];

export const numericAdvancedFields = new Set<(typeof advancedFields)[number]>([
  'hy2_up_mbps',
  'hy2_down_mbps',
  'shadowtls_version',
]);

export const inboundProtocols = ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria2', 'tuic', 'shadowtls'] as const;
export const inboundSecurities = ['none', 'tls', 'reality'] as const;

type InboundProtocol = (typeof inboundProtocols)[number];
type InboundSecurity = (typeof inboundSecurities)[number];
type InboundNetwork = string;

type InboundCapability = {
  core: 'xray' | 'sing-box';
  templateId: InboundTemplateId;
  templateLabel: string;
  templateSummary: string;
  networks: InboundNetwork[];
  defaultNetwork: InboundNetwork;
  defaultSecurity: InboundSecurity;
  securityByNetwork: Partial<Record<InboundNetwork, InboundSecurity[]>> & { default: InboundSecurity[] };
  visibleFields: string[];
  autoGenerateFields: string[];
  expertFields: string[];
  protocolAdvancedFields: InboundAdvancedField[];
  securityAdvancedFields: Partial<Record<InboundSecurity, InboundAdvancedField[]>>;
  credentialType: 'none' | 'uuid' | 'password' | 'credential_id_password' | 'username_password';
  subscription: 'none' | 'full';
  shareLink: boolean;
  localProxyInbound?: boolean;
};

export type InboundTemplateId =
  | 'recommended'
  | 'compatible'
  | 'password'
  | 'light'
  | 'local-socks'
  | 'local-http'
  | 'udp-fast'
  | 'low-latency'
  | 'handshake-mask';

const xrayNetworks = ['tcp', 'ws', 'grpc', 'h2', 'xhttp'];
const realityFields: InboundAdvancedField[] = ['reality_dest', 'reality_server_names', 'reality_short_id', 'reality_private_key', 'reality_public_key', 'tls_fingerprint'];
const xrayTlsFields: InboundAdvancedField[] = ['tls_cert_file', 'tls_key_file', 'tls_sni', 'tls_fingerprint', 'tls_alpn'];
const singboxTlsFields: InboundAdvancedField[] = ['tls_cert_file', 'tls_key_file', 'tls_sni'];
const inboundTemplateIds: InboundTemplateId[] = ['recommended', 'compatible', 'password', 'light', 'local-socks', 'local-http', 'udp-fast', 'low-latency', 'handshake-mask'];

export const inboundCapabilities: Record<InboundProtocol, InboundCapability> = {
  vless: {
    core: 'xray',
    templateId: 'recommended',
    templateLabel: '推荐节点',
    templateSummary: 'VLESS + TCP + REALITY',
    networks: xrayNetworks,
    defaultNetwork: 'tcp',
    defaultSecurity: 'reality',
    securityByNetwork: {
      default: ['none', 'tls'],
      tcp: ['none', 'tls', 'reality'],
      grpc: ['none', 'tls', 'reality'],
      xhttp: ['none', 'tls', 'reality'],
    },
    protocolAdvancedFields: [],
    securityAdvancedFields: { tls: xrayTlsFields, reality: realityFields },
    visibleFields: ['remark', 'port', 'public_host', 'reality_dest', 'reality_server_names', 'tls_certificate'],
    autoGenerateFields: ['uuid', 'client_uuid', 'reality_private_key', 'reality_public_key', 'reality_short_id'],
    expertFields: ['uuid', 'ws_path', 'ws_host', 'grpc_service_name', 'reality_short_id', 'reality_private_key', 'reality_public_key', 'tls_fingerprint', 'tls_alpn', 'xhttp_path', 'xhttp_mode'],
    credentialType: 'uuid',
    subscription: 'full',
    shareLink: true,
  },
  vmess: {
    core: 'xray',
    templateId: 'compatible',
    templateLabel: '兼容节点',
    templateSummary: 'VMess + WS + TLS',
    networks: xrayNetworks,
    defaultNetwork: 'ws',
    defaultSecurity: 'tls',
    securityByNetwork: { default: ['none', 'tls'] },
    protocolAdvancedFields: [],
    securityAdvancedFields: { tls: xrayTlsFields },
    visibleFields: ['remark', 'port', 'public_host', 'tls_sni', 'tls_certificate'],
    autoGenerateFields: ['uuid', 'client_uuid'],
    expertFields: ['uuid', 'ws_path', 'ws_host', 'grpc_service_name', 'tls_fingerprint', 'tls_alpn', 'xhttp_path', 'xhttp_mode'],
    credentialType: 'uuid',
    subscription: 'full',
    shareLink: true,
  },
  trojan: {
    core: 'xray',
    templateId: 'password',
    templateLabel: '密码节点',
    templateSummary: 'Trojan + TLS',
    networks: xrayNetworks,
    defaultNetwork: 'tcp',
    defaultSecurity: 'tls',
    securityByNetwork: {
      default: ['none', 'tls'],
      tcp: ['none', 'tls', 'reality'],
      grpc: ['none', 'tls', 'reality'],
      xhttp: ['none', 'tls', 'reality'],
    },
    protocolAdvancedFields: [],
    securityAdvancedFields: { tls: xrayTlsFields, reality: realityFields },
    visibleFields: ['remark', 'port', 'public_host', 'tls_sni', 'tls_certificate'],
    autoGenerateFields: ['uuid', 'client_password', 'reality_private_key', 'reality_public_key', 'reality_short_id'],
    expertFields: ['uuid', 'ws_path', 'ws_host', 'grpc_service_name', 'reality_dest', 'reality_server_names', 'reality_short_id', 'reality_private_key', 'reality_public_key', 'tls_fingerprint', 'tls_alpn', 'xhttp_path', 'xhttp_mode'],
    credentialType: 'password',
    subscription: 'full',
    shareLink: true,
  },
  shadowsocks: {
    core: 'xray',
    templateId: 'light',
    templateLabel: '轻量节点',
    templateSummary: 'Shadowsocks 2022',
    networks: ['tcp'],
    defaultNetwork: 'tcp',
    defaultSecurity: 'none',
    securityByNetwork: { default: ['none'] },
    protocolAdvancedFields: ['ss_method'],
    securityAdvancedFields: {},
    visibleFields: ['remark', 'port', 'public_host'],
    autoGenerateFields: ['uuid', 'shadowsocks_password'],
    expertFields: ['uuid', 'ss_method'],
    credentialType: 'none',
    subscription: 'full',
    shareLink: true,
  },
  socks: {
    core: 'xray',
    templateId: 'local-socks',
    templateLabel: '本地代理',
    templateSummary: 'SOCKS',
    networks: ['tcp'],
    defaultNetwork: 'tcp',
    defaultSecurity: 'none',
    securityByNetwork: { default: ['none'] },
    protocolAdvancedFields: [],
    securityAdvancedFields: {},
    visibleFields: ['remark', 'port'],
    autoGenerateFields: ['uuid', 'username', 'password'],
    expertFields: ['uuid'],
    credentialType: 'username_password',
    subscription: 'full',
    shareLink: true,
    localProxyInbound: true,
  },
  http: {
    core: 'xray',
    templateId: 'local-http',
    templateLabel: '本地代理',
    templateSummary: 'HTTP',
    networks: ['tcp'],
    defaultNetwork: 'tcp',
    defaultSecurity: 'none',
    securityByNetwork: { default: ['none'] },
    protocolAdvancedFields: [],
    securityAdvancedFields: {},
    visibleFields: ['remark', 'port'],
    autoGenerateFields: ['uuid', 'username', 'password'],
    expertFields: ['uuid'],
    credentialType: 'username_password',
    subscription: 'full',
    shareLink: true,
    localProxyInbound: true,
  },
  hysteria2: {
    core: 'sing-box',
    templateId: 'udp-fast',
    templateLabel: '高速 UDP',
    templateSummary: 'Hysteria2',
    networks: ['udp'],
    defaultNetwork: 'udp',
    defaultSecurity: 'tls',
    securityByNetwork: { default: ['tls'] },
    protocolAdvancedFields: ['hy2_up_mbps', 'hy2_down_mbps', 'hy2_obfs', 'hy2_obfs_password'],
    securityAdvancedFields: { tls: singboxTlsFields },
    visibleFields: ['remark', 'port', 'public_host', 'tls_sni', 'tls_certificate'],
    autoGenerateFields: ['uuid', 'client_password', 'hy2_obfs_password'],
    expertFields: ['uuid', 'hy2_up_mbps', 'hy2_down_mbps', 'hy2_obfs', 'hy2_obfs_password'],
    credentialType: 'password',
    subscription: 'full',
    shareLink: true,
  },
  tuic: {
    core: 'sing-box',
    templateId: 'low-latency',
    templateLabel: '高速低延迟',
    templateSummary: 'TUIC',
    networks: ['udp'],
    defaultNetwork: 'udp',
    defaultSecurity: 'tls',
    securityByNetwork: { default: ['tls'] },
    protocolAdvancedFields: ['tuic_congestion_control', 'tuic_zero_rtt'],
    securityAdvancedFields: { tls: singboxTlsFields },
    visibleFields: ['remark', 'port', 'public_host', 'tls_sni', 'tls_certificate'],
    autoGenerateFields: ['uuid', 'tuic_uuid', 'tuic_password'],
    expertFields: ['uuid', 'tuic_congestion_control', 'tuic_zero_rtt'],
    credentialType: 'credential_id_password',
    subscription: 'full',
    shareLink: true,
  },
  shadowtls: {
    core: 'sing-box',
    templateId: 'handshake-mask',
    templateLabel: '伪装握手',
    templateSummary: 'ShadowTLS',
    networks: ['tcp'],
    defaultNetwork: 'tcp',
    defaultSecurity: 'none',
    securityByNetwork: { default: ['none'] },
    protocolAdvancedFields: ['shadowtls_version', 'tls_sni'],
    securityAdvancedFields: {},
    visibleFields: ['remark', 'port', 'tls_sni'],
    autoGenerateFields: ['uuid', 'client_password'],
    expertFields: ['uuid', 'shadowtls_version'],
    credentialType: 'password',
    subscription: 'none',
    shareLink: false,
  },
};

let activeInboundCapabilities: Record<InboundProtocol, InboundCapability> = inboundCapabilities;
let activeInboundProtocols: InboundProtocol[] = [...inboundProtocols];

export function applyInboundCapabilitiesFromAPI(capabilities: ApiInboundCapability[] | undefined | null) {
  const next: Partial<Record<InboundProtocol, InboundCapability>> = {};
  const nextProtocols: InboundProtocol[] = [];
  for (const item of capabilities || []) {
    const protocol = String(item?.protocol || '').trim().toLowerCase() as InboundProtocol;
    if (!inboundProtocols.includes(protocol)) continue;
    nextProtocols.push(protocol);
    next[protocol] = normalizeCapabilityFromAPI(item, inboundCapabilities[protocol]);
  }
  activeInboundCapabilities = nextProtocols.length > 0 ? { ...inboundCapabilities, ...next } : inboundCapabilities;
  activeInboundProtocols = nextProtocols.length > 0 ? nextProtocols : [...inboundProtocols];
}

export function resetInboundCapabilitiesForTest() {
  activeInboundCapabilities = inboundCapabilities;
  activeInboundProtocols = [...inboundProtocols];
}

function normalizeCapabilityFromAPI(item: ApiInboundCapability, fallback: InboundCapability): InboundCapability {
  const rawSecurityByNetwork = item.security_by_network && typeof item.security_by_network === 'object' ? item.security_by_network : {};
  const rawDefaultSecurities = Array.isArray(rawSecurityByNetwork.default) ? rawSecurityByNetwork.default : fallback.securityByNetwork.default;
  const securityByNetwork: InboundCapability['securityByNetwork'] = { ...fallback.securityByNetwork, default: normalizeSecurities(rawDefaultSecurities) };
  for (const [network, securities] of Object.entries(rawSecurityByNetwork)) {
    if (!Array.isArray(securities)) continue;
    securityByNetwork[network] = normalizeSecurities(securities);
  }
  const rawAdvancedFields = Array.isArray(item.advanced_fields) ? item.advanced_fields : [];
  const advanced = new Set(rawAdvancedFields.filter(isInboundAdvancedField));
  const securityAdvancedFields: InboundCapability['securityAdvancedFields'] = {};
  if (advanced.has('tls_cert_file')) {
    securityAdvancedFields.tls = ['tls_cert_file', 'tls_key_file', 'tls_sni', 'tls_fingerprint', 'tls_alpn'].filter((field): field is InboundAdvancedField => advanced.has(field as InboundAdvancedField));
  }
  if (advanced.has('reality_dest')) {
    securityAdvancedFields.reality = ['reality_dest', 'reality_server_names', 'reality_short_id', 'reality_private_key', 'reality_public_key', 'tls_fingerprint'].filter((field): field is InboundAdvancedField => advanced.has(field as InboundAdvancedField));
  }
  const securityFields = new Set(Object.values(fallback.securityAdvancedFields).flat());
  const protocolAdvancedFields = Array.from(advanced).filter((field) => fallback.protocolAdvancedFields.includes(field) || !securityFields.has(field));
  return {
    core: item.core === 'sing-box' ? 'sing-box' : 'xray',
    templateId: normalizeTemplateId(item.template_id, fallback.templateId),
    templateLabel: item.template_label || fallback.templateLabel,
    templateSummary: item.template_summary || fallback.templateSummary,
    networks: Array.isArray(item.networks) && item.networks.length ? item.networks : fallback.networks,
    defaultNetwork: item.default_network || fallback.defaultNetwork,
    defaultSecurity: normalizeSecurity(item.default_security, fallback.defaultSecurity),
    securityByNetwork,
    visibleFields: normalizeStringList(item.visible_fields, fallback.visibleFields),
    autoGenerateFields: normalizeStringList(item.auto_generate_fields, fallback.autoGenerateFields),
    expertFields: normalizeStringList(item.expert_fields, fallback.expertFields),
    protocolAdvancedFields,
    securityAdvancedFields,
    credentialType: normalizeCredentialType(item.credential_type, fallback.credentialType),
    subscription: item.subscription === 'none' ? 'none' : 'full',
    shareLink: typeof item.share_link === 'boolean' ? item.share_link : fallback.shareLink,
    localProxyInbound: item.local_proxy_inbound,
  };
}

function normalizeStringList(value: unknown, fallback: string[]): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : fallback;
}

function normalizeTemplateId(value: unknown, fallback: InboundTemplateId): InboundTemplateId {
  return inboundTemplateIds.includes(value as InboundTemplateId) ? value as InboundTemplateId : fallback;
}

function normalizeSecurities(values: string[]): InboundSecurity[] {
  const securities = values.map((value) => normalizeSecurity(value, 'none'));
  return securities.length ? securities : ['none'];
}

function normalizeSecurity(value: string, fallback: InboundSecurity): InboundSecurity {
  return inboundSecurities.includes(value as InboundSecurity) ? value as InboundSecurity : fallback;
}

function normalizeCredentialType(value: string, fallback: InboundCapability['credentialType']): InboundCapability['credentialType'] {
  return ['none', 'uuid', 'password', 'credential_id_password', 'username_password'].includes(value) ? value as InboundCapability['credentialType'] : fallback;
}

function isInboundAdvancedField(value: string): value is InboundAdvancedField {
  return advancedFields.includes(value as InboundAdvancedField);
}

type SortKey = 'id' | 'port' | 'protocol' | 'clients';
type InboundListColumns = 1 | 2;

export default function InboundsPage() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const { showToast } = useToast();
  const { text } = useI18n();
  const visible = usePageVisible();
  const [editingInbound, setEditingInbound] = useState<Inbound | null>(null);
  const [clientInbound, setClientInbound] = useState<Inbound | null>(null);
  const [editingClient, setEditingClient] = useState<{ inbound: Inbound; client: Client } | null>(null);
  const [qrLink, setQRLink] = useState<{ title: string; value: string; dataURL: string } | null>(null);
  const [search, setSearch] = useState('');
  const [inboundColumns, setInboundColumns] = useState<InboundListColumns>(2);
  const [sort, setSort] = useState<SortKey>('id');
  const [, setCapabilityVersion] = useState(0);
  const capabilities = useQuery({ queryKey: ['inbound-capabilities'], queryFn: api.inboundCapabilities, staleTime: 300_000, retry: false });
  const inbounds = useQuery({ queryKey: ['inbounds'], queryFn: api.inbounds, staleTime: 30_000 });
  const inboundTraffic = useQuery({
    queryKey: ['inbounds', 'traffic'],
    queryFn: api.inboundTraffic,
    enabled: visible && Boolean(inbounds.data),
    refetchInterval: visible ? 10_000 : false,
    staleTime: 5_000,
  });
  useEffect(() => {
    if (!inboundTraffic.data) return;
    queryClient.setQueryData<Inbound[]>(['inbounds'], (current) => mergeInboundTraffic(current || [], inboundTraffic.data || []));
  }, [inboundTraffic.data, queryClient]);
  useEffect(() => {
    if (capabilities.data) {
      applyInboundCapabilitiesFromAPI(capabilities.data);
      setCapabilityVersion((version) => version + 1);
    } else if (capabilities.isError) {
      resetInboundCapabilitiesForTest();
      setCapabilityVersion((version) => version + 1);
    }
  }, [capabilities.data, capabilities.isError]);
  const refresh = () => refreshInboundDependencies(queryClient);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = (inbounds.data || []).filter((item) => !q || [item.remark, item.protocol, inboundCore(item), String(item.port), item.network, item.security].join(' ').toLowerCase().includes(q));
    return [...list].sort((a, b) => {
      if (sort === 'port') return a.port - b.port;
      if (sort === 'protocol') return a.protocol.localeCompare(b.protocol);
      if (sort === 'clients') return (b.clients || []).length - (a.clients || []).length;
      return a.id - b.id;
    });
  }, [inbounds.data, search, sort]);

  const toggleInbound = useMutation({
    mutationFn: (item: Inbound) => api.toggleInbound(item.id, !item.enabled),
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已保存，但核心配置未生效', showToast, text)) {
        showToast(text('节点状态已更新'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('节点状态更新失败')), 'error'),
  });
  const deleteInbound = useMutation({
    mutationFn: api.deleteInbound,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已删除，但核心配置未生效', showToast, text)) {
        showToast(text('节点已删除'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('删除节点失败')), 'error'),
  });
  const deleteClient = useMutation({
    mutationFn: ({ inboundId, id }: { inboundId: number; id: number }) => api.deleteClient(inboundId, id),
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已删除，但核心配置未生效', showToast, text)) {
        showToast(text('客户端已删除'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('删除客户端失败')), 'error'),
  });
  const toggleClient = useMutation({
    mutationFn: ({ inboundId, client }: { inboundId: number; client: Client }) => api.toggleClient(inboundId, client.id, !client.enabled),
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已保存，但核心配置未生效', showToast, text)) {
        showToast(text('客户端状态已更新'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('客户端状态更新失败')), 'error'),
  });
  const resetTraffic = useMutation({
    mutationFn: ({ inboundId, id }: { inboundId: number; id: number }) => api.resetClientTraffic(inboundId, id),
    onSuccess: () => {
      showToast(text('累计用量已重置'), 'success');
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('重置累计用量失败')), 'error'),
  });

  if (inbounds.isLoading) return <LoadingBlock />;

  return (
    <div className="page-stack">
      <PageTitle
        title={text('节点与客户端')}
        description={text('创建节点、管理客户端凭据、复制节点链接和查看流量状态。')}
        action={
          <button className="btn primary" onClick={() => setEditingInbound(createDefaultInbound())}>
            <Plus className="h-4 w-4" /> {text('新增节点')}
          </button>
        }
      />
      <div className="toolbar">
        <input className="max-w-md" placeholder={text('搜索节点、协议、端口...')} value={search} onChange={(e) => setSearch(e.target.value)} />
        <div className="segmented-control" aria-label={text('节点列表布局')}>
          <button type="button" className={inboundColumns === 1 ? 'active' : ''} onClick={() => setInboundColumns(1)} aria-pressed={inboundColumns === 1} title={text('一行一张')}>
            <RectangleHorizontal className="h-4 w-4" />
          </button>
          <button type="button" className={inboundColumns === 2 ? 'active' : ''} onClick={() => setInboundColumns(2)} aria-pressed={inboundColumns === 2} title={text('一行两张')}>
            <Columns2 className="h-4 w-4" />
          </button>
        </div>
        <select className="w-44" value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
          <option value="id">{text('按创建顺序')}</option>
          <option value="port">{text('按端口')}</option>
          <option value="protocol">{text('按协议')}</option>
          <option value="clients">{text('按客户端数')}</option>
        </select>
      </div>
      {filtered.length === 0 ? (
        <EmptyState title={text('暂无节点')} description={text('创建第一个节点后，可继续为它添加客户端并复制节点链接。')} />
      ) : (
        <div className={`inbound-card-grid ${inboundColumns === 2 ? 'inbound-card-grid-2' : ''}`}>
          {filtered.map((inbound) => (
            <div key={inbound.id} className="resource-card">
              <div className="resource-header">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="truncate text-base font-semibold">{inbound.remark || `${inbound.protocol}:${inbound.port}`}</h2>
                    <ProtocolBadge protocol={inbound.protocol} />
                    <StatusBadge enabled={inbound.enabled} />
                  </div>
                  <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-panel-muted">
                    <span>:{inbound.port}</span>
                    <span>{inbound.network || 'tcp'} / {inbound.security || 'none'}</span>
                    <span>{(inbound.clients || []).length} {text('客户端')}</span>
                    <span>{text(supportsInboundShareLink(inbound.protocol) ? '支持节点链接' : '暂不支持分享链接')}</span>
                  </div>
                </div>
                <div className="action-row">
                  <SpinnerButton className={toggleButtonClass(inbound.enabled)} loading={toggleInbound.isPending} onClick={() => toggleInbound.mutate(inbound)} title={text('启停')}>
                    <Power className="h-4 w-4" />
                  </SpinnerButton>
                  <button className="icon-button" onClick={() => setEditingInbound(inbound)} title={text('编辑')}>
                    <Edit2 className="h-4 w-4" />
                  </button>
                  <button className="icon-button danger-text" onClick={async () => (await confirm({ title: text('删除节点？'), description: text('该节点下的客户端也会被删除。'), tone: 'danger' })) && deleteInbound.mutate(inbound.id)} title={text('删除')}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
              <div className="mt-3 grid gap-2 text-xs text-panel-muted sm:grid-cols-4">
                <MetaItem label={text('上行')} value={formatBytes(inbound.traffic_up)} />
                <MetaItem label={text('下行')} value={formatBytes(inbound.traffic_down)} />
                <MetaItem label={text('合计')} value={formatBytes(inbound.traffic_total)} />
                <MetaItem label={text('当前速率')} value={`${formatBytes(Number(inbound.rate_up || 0))}/s ↑ / ${formatBytes(Number(inbound.rate_down || 0))}/s ↓`} />
                <MetaItem label={text('统计状态')} value={trafficStatusLabel(inbound.traffic_status, text)} />
              </div>
              <div className="mt-4 border-t border-panel-line pt-3">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="text-sm font-medium">{text('客户端')}</div>
                  <button className="btn secondary h-8" onClick={() => setClientInbound(inbound)}>
                    <Plus className="h-4 w-4" /> {text('新增客户端')}
                  </button>
                </div>
                <div className="grid gap-2">
                  {(inbound.clients || []).map((client) => (
                    <ClientRow
                      key={client.id}
                      inbound={inbound}
                      client={mergeClientTraffic(inbound, client)}
                      onCopyShare={() => copyNodeLink(client, showToast, text)}
                      onShowQR={() => showClientQRCode(client, showToast, setQRLink, text)}
                      shareSupported={supportsInboundShareLink(inbound.protocol)}
                      onToggle={() => toggleClient.mutate({ inboundId: inbound.id, client })}
                      onEdit={() => setEditingClient({ inbound, client })}
                      onReset={async () => (await confirm({ title: text('重置累计用量？'), description: text('会清零 MiGate 维护的业务累计用量，并以当前核心计数作为新的基线。') })) && resetTraffic.mutate({ inboundId: inbound.id, id: client.id })}
                      onDelete={async () => (await confirm({ title: text('删除客户端？'), tone: 'danger' })) && deleteClient.mutate({ inboundId: inbound.id, id: client.id })}
                    />
                  ))}
                  {(inbound.clients || []).length === 0 ? <EmptyState title={text('暂无客户端')} /> : null}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      <Suspense fallback={null}>
        {editingInbound ? <InboundModal inbound={editingInbound} onClose={() => setEditingInbound(null)} onSaved={refresh} /> : null}
        {clientInbound ? <ClientModal inbound={clientInbound} onClose={() => setClientInbound(null)} onSaved={refresh} /> : null}
        {editingClient ? <ClientModal inbound={editingClient.inbound} client={editingClient.client} onClose={() => setEditingClient(null)} onSaved={refresh} /> : null}
      </Suspense>
      {qrLink ? (
        <Modal
          open={!!qrLink}
          title={qrLink.title ? `${qrLink.title} ${text('节点二维码')}` : text('节点二维码')}
          onClose={() => setQRLink(null)}
          panelClassName="qr-modal-panel"
          footer={<button className="btn primary" onClick={() => setQRLink(null)}>{text('完成')}</button>}
        >
          <div className="qr-panel">
            <img src={qrLink.dataURL} alt={text('节点二维码')} />
            <div className="qr-link-text">{qrLink.value}</div>
            <button className="btn secondary" onClick={() => copyText(qrLink.value, text('节点链接已复制'), showToast, text)}>
              <Copy className="h-4 w-4" /> {text('复制节点链接')}
            </button>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}

function ClientRow({
  client,
  onCopyShare,
  onShowQR,
  onToggle,
  onEdit,
  onReset,
  onDelete,
  shareSupported,
}: {
  inbound: Inbound;
  client: Client;
  onCopyShare: () => void;
  onShowQR: () => void;
  onToggle: () => void;
  onEdit: () => void;
  onReset: () => void;
  onDelete: () => void;
  shareSupported: boolean;
}) {
  const { text } = useI18n();
  const used = Number(client.up || 0) + Number(client.down || 0);
  const limit = Number(client.traffic_limit || 0);
  return (
    <div className="client-row">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate font-medium">{client.email}</span>
          <StatusBadge enabled={client.enabled} />
        </div>
        <div className="mt-1 break-all text-xs text-panel-muted">{client.uuid}</div>
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-panel-muted">
          <MetaItem label={text('上行')} value={formatBytes(client.up)} />
          <MetaItem label={text('下行')} value={formatBytes(client.down)} />
          <MetaItem label={text('限额')} value={limit > 0 ? `${formatBytes(used)} / ${formatBytes(limit)}` : text('不限制')} />
          <MetaItem label={text('过期')} value={client.expiry_at ? new Date(client.expiry_at * 1000).toLocaleString() : text('不限制')} />
          <MetaItem label={text('当前速率')} value={`${formatBytes(Number(client.rate_up || 0))}/s ↑ / ${formatBytes(Number(client.rate_down || 0))}/s ↓`} />
          <MetaItem label={text('统计状态')} value={trafficStatusLabel(client.traffic_status, text)} />
        </div>
      </div>
      <div className="action-row">
        {shareSupported ? <button className="icon-button" onClick={onCopyShare} title={text('复制节点链接')}><Copy className="h-4 w-4" /></button> : <span className="client-link-status">{text('暂不支持分享链接')}</span>}
        {shareSupported ? <button className="icon-button" onClick={onShowQR} title={text('显示二维码')}><QrCode className="h-4 w-4" /></button> : null}
        <button className={toggleButtonClass(client.enabled)} onClick={onToggle} title={text('启停')}><Power className="h-4 w-4" /></button>
        <button className="icon-button" onClick={onEdit} title={text('编辑')}><Edit2 className="h-4 w-4" /></button>
        <button className="icon-button" onClick={onReset} title={text('重置累计用量')}><RotateCcw className="h-4 w-4" /></button>
        <button className="icon-button danger-text" onClick={onDelete} title={text('删除')}><Trash2 className="h-4 w-4" /></button>
      </div>
    </div>
  );
}

function MetaItem({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex gap-1">
      <span>{label}</span>
      <span>{value}</span>
    </span>
  );
}

function refreshInboundDependencies(queryClient: ReturnType<typeof useQueryClient>) {
  refreshTopologyDependencies(queryClient);
}

const protocolBadgeClasses: Record<string, string> = {
  vless: 'protocol-vless',
  vmess: 'protocol-vmess',
  trojan: 'protocol-trojan',
  shadowsocks: 'protocol-shadowsocks',
  hysteria2: 'protocol-hysteria2',
  tuic: 'protocol-tuic',
  shadowtls: 'protocol-shadowtls',
};

function ProtocolBadge({ protocol }: { protocol: string }) {
  const key = String(protocol || '').toLowerCase();
  return <span className={`protocol-badge ${protocolBadgeClasses[key] || 'protocol-default'}`}>{protocol || 'unknown'}</span>;
}

export function createDefaultInbound(): Inbound {
  const seed: Inbound = {
    id: 0,
    remark: '',
    protocol: 'vless',
    port: 0,
    network: 'tcp',
    security: 'reality',
    enabled: true,
    uuid: generatedProtocolCredential('vless'),
    clients: [],
    reality_dest: 'www.cloudflare.com:443',
    reality_server_names: 'www.cloudflare.com',
    ss_method: '2022-blake3-aes-128-gcm',
    xhttp_mode: 'stream-one',
    hy2_up_mbps: 100,
    hy2_down_mbps: 100,
    tuic_congestion_control: 'bbr',
    shadowtls_version: 3,
  };
  return { ...seed, ...applyInboundTemplate(seed, 'recommended'), id: 0, clients: [] };
}

export function inboundFormValues(inbound: Inbound): InboundValues {
  const base = {
    remark: inbound.remark || '',
    protocol: inbound.protocol as InboundValues['protocol'],
    port: inbound.port || 0,
    network: inbound.network || 'tcp',
    security: inbound.security || 'none',
    uuid: String(inbound.uuid || ''),
    enabled: inbound.enabled ?? true,
  } as InboundValues;
  for (const key of advancedFields) {
    const value = inbound[key];
    (base as Record<string, unknown>)[key] = value ?? defaultAdvancedValue(key);
  }
  return normalizeInboundCombination(base);
}

export function buildFullInboundPayload(inbound: Inbound | null, values: InboundValues, initialClient?: ReturnType<typeof buildClientPayload> | null): Record<string, unknown> {
  const payload: Record<string, unknown> = inbound ? { ...inbound } : {};
  delete payload.id;
  delete payload.clients;
  delete payload.traffic_up;
  delete payload.traffic_down;
  delete payload.traffic_total;
  delete payload.traffic_stats_source;
  delete payload.realtime_stats_source;
  delete payload.client_traffic;
  const normalized = normalizeInboundCombination(values);
  Object.assign(payload, normalized);
  payload.port = Number(normalized.port || 0);
  for (const key of advancedFields) {
    payload[key] = isInboundAdvancedFieldEnabled(normalized, key) ? normalizeAdvancedValue(key, payload[key]) : defaultAdvancedValue(key);
  }
  if (!inbound?.id && initialClient) {
    payload.initial_client = initialClient;
  } else {
    delete payload.initial_client;
  }
  return payload;
}

const inboundTemplates: Array<{ id: InboundTemplateId; label: string; description: string; values: Partial<InboundValues> }> = [
  {
    id: 'recommended',
    label: '推荐节点：VLESS + TCP + REALITY',
    description: '默认推荐，自动生成 REALITY 密钥和 Short ID。',
    values: {
      protocol: 'vless',
      port: 0,
      network: 'tcp',
      security: 'reality',
      reality_dest: 'www.cloudflare.com:443',
      reality_server_names: 'www.cloudflare.com',
      tls_fingerprint: 'chrome',
    },
  },
  {
    id: 'compatible',
    label: '兼容节点：VMess + WS + TLS',
    description: '适合旧客户端或 WebSocket 中转场景。',
    values: {
      protocol: 'vmess',
      port: 0,
      network: 'ws',
      security: 'tls',
      ws_path: '/migate',
      ws_host: 'example.com',
      tls_sni: 'example.com',
      tls_alpn: 'http/1.1',
    },
  },
  {
    id: 'password',
    label: '密码节点：Trojan + TLS',
    description: '用密码连接，配置简单，依赖 TLS 证书。',
    values: {
      protocol: 'trojan',
      port: 0,
      network: 'tcp',
      security: 'tls',
      tls_sni: 'example.com',
      tls_alpn: 'http/1.1',
    },
  },
  {
    id: 'light',
    label: '轻量节点：Shadowsocks 2022',
    description: '轻量加密，使用节点级密钥。',
    values: {
      protocol: 'shadowsocks',
      port: 0,
      network: 'tcp',
      security: 'none',
      ss_method: '2022-blake3-aes-128-gcm',
    },
  },
  {
    id: 'local-socks',
    label: '本地代理：SOCKS',
    description: '本机或内网使用，不生成分享链接。',
    values: {
      protocol: 'socks',
      port: 0,
      network: 'tcp',
      security: 'none',
    },
  },
  {
    id: 'local-http',
    label: '本地代理：HTTP',
    description: '本机或内网使用，不生成分享链接。',
    values: {
      protocol: 'http',
      port: 0,
      network: 'tcp',
      security: 'none',
    },
  },
  {
    id: 'udp-fast',
    label: '高速 UDP：Hysteria2',
    description: '面向 UDP 和弱网吞吐，使用 sing-box。',
    values: {
      protocol: 'hysteria2',
      port: 0,
      network: 'udp',
      security: 'tls',
      tls_sni: 'example.com',
      hy2_up_mbps: 100,
      hy2_down_mbps: 100,
      hy2_obfs: 'salamander',
    },
  },
  {
    id: 'low-latency',
    label: '高速低延迟：TUIC',
    description: '低延迟 UDP 节点，自动生成 UUID 和密码。',
    values: {
      protocol: 'tuic',
      port: 0,
      network: 'udp',
      security: 'tls',
      tls_sni: 'example.com',
      tuic_congestion_control: 'bbr',
      tuic_zero_rtt: false,
    },
  },
  {
    id: 'handshake-mask',
    label: '伪装握手：ShadowTLS',
    description: '伪装握手协议，暂不显示分享链接。',
    values: {
      protocol: 'shadowtls',
      port: 0,
      network: 'tcp',
      security: 'none',
      tls_sni: 'www.cloudflare.com',
      shadowtls_version: 3,
    },
  },
];

export function inboundTemplateOptions() {
  return inboundTemplates.map(({ id, label, description }) => ({ id, label, description }));
}

export function applyInboundTemplate(current: InboundValues | Inbound, id: InboundTemplateId): InboundValues {
  const template = inboundTemplates.find((item) => item.id === id) || inboundTemplates[0];
  const nextProtocol = template.values.protocol || current.protocol || 'vless';
  const nextUUID = normalizedProtocolCredential(current.uuid, nextProtocol);
  const next = normalizeInboundCombination(inboundFormValues({ id: 'id' in current ? current.id : 0, ...clearTemplateAdvancedFields(current, id), ...template.values, uuid: nextUUID, enabled: current.enabled ?? true } as Inbound));
  if (template.id === 'recommended') next.reality_short_id = randomHex(4);
  if (template.id === 'udp-fast') {
    next.hy2_obfs_password = randomSecret(18);
  }
  return next;
}

function clearTemplateAdvancedFields(current: InboundValues | Inbound, id: InboundTemplateId): InboundValues {
  const next = inboundFormValues(current as Inbound);
  const keep = new Set<InboundAdvancedField>(templateAdvancedFields[id]);
  for (const key of advancedFields) {
    if (!keep.has(key)) {
      (next as Record<string, unknown>)[key] = defaultAdvancedValue(key);
    }
  }
  return next;
}

const templateAdvancedFields: Record<InboundTemplateId, InboundAdvancedField[]> = {
  recommended: ['reality_dest', 'reality_server_names', 'reality_short_id', 'reality_private_key', 'reality_public_key', 'tls_fingerprint'],
  compatible: ['ws_path', 'ws_host', 'tls_cert_file', 'tls_key_file', 'tls_sni', 'tls_fingerprint', 'tls_alpn'],
  password: ['tls_cert_file', 'tls_key_file', 'tls_sni', 'tls_fingerprint', 'tls_alpn'],
  light: ['ss_method'],
  'local-socks': [],
  'local-http': [],
  'udp-fast': ['tls_cert_file', 'tls_key_file', 'tls_sni', 'hy2_up_mbps', 'hy2_down_mbps', 'hy2_obfs', 'hy2_obfs_password'],
  'low-latency': ['tls_cert_file', 'tls_key_file', 'tls_sni', 'tuic_congestion_control', 'tuic_zero_rtt'],
  'handshake-mask': ['tls_sni', 'shadowtls_version'],
};

export function sanitizeInboundFormValues(values: InboundValues, changes: Partial<Pick<InboundValues, 'protocol' | 'network' | 'security'>> = {}): InboundValues {
  const changedProtocol = changes.protocol ? asInboundProtocol(changes.protocol) : undefined;
  const protocolDefaults = changedProtocol ? activeInboundCapabilities[changedProtocol] : undefined;
  const next = normalizeInboundCombination({
    ...values,
    ...changes,
    uuid: changedProtocol ? normalizedProtocolCredential(values.uuid, changedProtocol) : values.uuid,
    network: changes.network ?? protocolDefaults?.defaultNetwork ?? values.network,
    security: changes.security ?? protocolDefaults?.defaultSecurity ?? values.security,
  });
  const enabled = enabledInboundAdvancedFields(next);
  for (const key of advancedFields) {
    if (!enabled.has(key)) {
      (next as Record<string, unknown>)[key] = defaultAdvancedValue(key);
    } else if (isBlankAdvancedValue(key, next[key])) {
      (next as Record<string, unknown>)[key] = seededAdvancedValue(key);
    }
  }
  return next;
}

export function normalizeInboundCombination(values: InboundValues): InboundValues {
  const protocol = asInboundProtocol(values.protocol);
  const capability = activeInboundCapabilities[protocol];
  const network = capability.networks.includes(values.network) ? values.network : capability.defaultNetwork;
  const securities = allowedInboundSecurities(protocol, network);
  const security = securities.includes(values.security as InboundSecurity) ? values.security as InboundSecurity : preferredInboundSecurity(capability, securities, values.security);
  return { ...values, protocol, network, security };
}

export function allowedInboundNetworks(protocol: string): string[] {
  return activeInboundCapabilities[asInboundProtocol(protocol)].networks;
}

export function allowedInboundSecurities(protocol: string, network: string): InboundSecurity[] {
  const capability = activeInboundCapabilities[asInboundProtocol(protocol)];
  return capability.securityByNetwork[network] || capability.securityByNetwork.default;
}

export function supportsInboundShareLink(protocol: string): boolean {
  return activeInboundCapabilities[asInboundProtocol(protocol)].shareLink;
}

export function inboundCredentialType(protocol: string) {
  return activeInboundCapabilities[asInboundProtocol(protocol)].credentialType;
}

export function isInboundAdvancedFieldEnabled(values: Pick<InboundValues, 'protocol' | 'network' | 'security'>, key: InboundAdvancedField): boolean {
  const normalized = normalizeInboundCombination(values as InboundValues);
  return enabledInboundAdvancedFields(normalized).has(key);
}

export function enabledInboundAdvancedFields(values: Pick<InboundValues, 'protocol' | 'network' | 'security'>): Set<InboundAdvancedField> {
  const protocol = asInboundProtocol(values.protocol);
  const capability = activeInboundCapabilities[protocol];
  const fields = new Set<InboundAdvancedField>(capability.protocolAdvancedFields);
  const security = values.security as InboundSecurity;
  for (const key of capability.securityAdvancedFields[security] || []) fields.add(key);
  if (values.network === 'ws' || values.network === 'h2') {
    fields.add('ws_path');
    fields.add('ws_host');
  }
  if (values.network === 'grpc') fields.add('grpc_service_name');
  if (values.network === 'xhttp') {
    fields.add('xhttp_path');
    fields.add('xhttp_mode');
  }
  return fields;
}

function asInboundProtocol(protocol: string): InboundProtocol {
  const normalized = String(protocol || '').toLowerCase() as InboundProtocol;
  if (activeInboundProtocols.includes(normalized)) return normalized;
  return inboundProtocols.includes(normalized) ? normalized : 'vless';
}

export function inboundProtocolOptions(): InboundProtocol[] {
  return [...activeInboundProtocols];
}

function preferredInboundSecurity(capability: InboundCapability, securities: InboundSecurity[], current?: string): InboundSecurity {
  if (securities.includes(capability.defaultSecurity)) return capability.defaultSecurity;
  if (current === 'reality' && securities.includes('tls')) return 'tls';
  return securities[0] || 'none';
}

function isBlankAdvancedValue(key: InboundAdvancedField, value: unknown): boolean {
  const current = normalizeAdvancedValue(key, value);
  return current === defaultAdvancedValue(key);
}

function seededAdvancedValue(key: InboundAdvancedField): string | number | boolean {
  if (key === 'reality_dest') return 'www.cloudflare.com:443';
  if (key === 'reality_server_names') return 'www.cloudflare.com';
  if (key === 'ss_method') return '2022-blake3-aes-128-gcm';
  if (key === 'xhttp_mode') return 'stream-one';
  if (key === 'hy2_up_mbps' || key === 'hy2_down_mbps') return 100;
  if (key === 'tuic_congestion_control') return 'bbr';
  if (key === 'shadowtls_version') return 3;
  return defaultAdvancedValue(key);
}

function defaultAdvancedValue(key: (typeof advancedFields)[number]): string | number | boolean {
  if (numericAdvancedFields.has(key)) return 0;
  if (key === 'tuic_zero_rtt') return false;
  return '';
}

function normalizeAdvancedValue(key: (typeof advancedFields)[number], value: unknown): string | number | boolean {
  if (numericAdvancedFields.has(key)) {
    const n = Number(value ?? 0);
    return Number.isFinite(n) ? n : 0;
  }
  if (key === 'tuic_zero_rtt') return Boolean(value);
  return value == null ? '' : String(value);
}

export function hasAttachableSettingCert(cert?: CertStatus | null) {
  return Boolean(cert?.issued && cert.cert_path.trim() && cert.key_path.trim());
}

function mergeClientTraffic(inbound: Inbound, client: Client): Client {
  const live = inbound.client_traffic?.[String(client.id)] || inbound.client_traffic?.[client.id as unknown as string];
  return {
    ...client,
    up: Number(live?.up ?? client.up ?? 0),
    down: Number(live?.down ?? client.down ?? 0),
    rate_up: Number(live?.rate_up ?? client.rate_up ?? 0),
    rate_down: Number(live?.rate_down ?? client.rate_down ?? 0),
    xray_up: Number(live?.xray_up ?? client.xray_up ?? 0),
    xray_down: Number(live?.xray_down ?? client.xray_down ?? 0),
    traffic_status: live?.status || client.traffic_status || inbound.traffic_status,
    traffic_message: live?.message || client.traffic_message || inbound.traffic_message,
    traffic_stats_source: live?.source || client.traffic_stats_source || inbound.traffic_stats_source,
    realtime_stats_source: live?.realtime_source || client.realtime_stats_source || inbound.realtime_stats_source,
  };
}

export function mergeInboundTraffic(current: Inbound[], traffic: Inbound[]): Inbound[] {
  const byID = new Map(traffic.map((inbound) => [inbound.id, inbound]));
  return current.map((inbound) => {
    const update = byID.get(inbound.id);
    if (!update) return inbound;
    return {
      ...inbound,
      enabled: update.enabled,
      clients: mergeClients(inbound.clients || [], update.clients || [], update.client_traffic),
      traffic_up: update.traffic_up,
      traffic_down: update.traffic_down,
      traffic_total: update.traffic_total,
      rate_up: update.rate_up,
      rate_down: update.rate_down,
      traffic_status: update.traffic_status,
      traffic_message: update.traffic_message,
      traffic_stats_source: update.traffic_stats_source,
      realtime_stats_source: update.realtime_stats_source,
      client_traffic: update.client_traffic,
    };
  });
}

function mergeClients(current: Client[], traffic: Client[], clientTraffic?: Inbound['client_traffic']): Client[] {
  const byID = new Map(traffic.map((client) => [client.id, client]));
  return current.map((client) => {
    const update = byID.get(client.id);
    if (!update) return client;
    return {
      ...client,
      enabled: update.enabled,
      up: update.up,
      down: update.down,
      rate_up: clientTraffic?.[String(client.id)]?.rate_up ?? update.rate_up,
      rate_down: clientTraffic?.[String(client.id)]?.rate_down ?? update.rate_down,
      traffic_status: clientTraffic?.[String(client.id)]?.status ?? update.traffic_status,
      traffic_message: clientTraffic?.[String(client.id)]?.message ?? update.traffic_message,
      traffic_limit: update.traffic_limit,
      expiry_at: update.expiry_at,
    };
  });
}

export function clientFormValues(inbound: Inbound, client?: Client): ClientValues {
  const generated = client ? emptyClientCredentialValues() : generatedClientCredentialValues(inbound.protocol);
  const credentialType = inboundCredentialType(inbound.protocol);
  let uuid = client?.uuid || generated.uuid;
  let credentialID = client?.credential_id || generated.credential_id;
  let password = client?.password || generated.password;
  if (credentialType === 'uuid') {
    credentialID = client?.credential_id || client?.uuid || generated.credential_id;
    uuid = credentialID;
  } else if (credentialType === 'password') {
    password = client?.password || client?.uuid || generated.password;
    uuid = password;
    credentialID = client?.credential_id || '';
  } else if (credentialType === 'credential_id_password' || credentialType === 'username_password') {
    credentialID = client?.credential_id || client?.uuid || generated.credential_id;
    uuid = credentialID;
    password = client?.password || generated.password;
  } else if (credentialType === 'none') {
    credentialID = '';
    password = '';
  }
  return {
    email: client?.email || defaultClientName(inbound.remark),
    uuid,
    credential_id: credentialID,
    password,
    enabled: client?.enabled ?? true,
    traffic_limit_gb: bytesToGB(client?.traffic_limit || 0),
    ...expiryToForm(client?.expiry_at || 0),
  };
}

export function defaultClientName(inboundRemark?: string) {
  const remark = String(inboundRemark || '').trim();
  return remark ? `${remark} 首个客户端` : '首个客户端';
}

export function buildClientPayload(values: ClientValues, protocol = 'vless'): { email: string; uuid: string; credential_id: string; password: string; enabled: boolean; traffic_limit: number; expiry_at: number } {
  const type = inboundCredentialType(protocol);
  const password = values.password || '';
  let credentialID = values.credential_id || values.uuid || '';
  let uuid = credentialID || password || '';
  if (type === 'password') {
    credentialID = values.credential_id || '';
    uuid = password || values.uuid || '';
  } else if (type === 'none') {
    credentialID = '';
    uuid = values.uuid || '';
  } else if (type === 'credential_id_password' || type === 'username_password') {
    credentialID = values.credential_id || values.uuid || '';
    uuid = credentialID;
  }
  return {
    email: values.email,
    uuid,
    credential_id: credentialID,
    password,
    enabled: values.enabled,
    traffic_limit: gbToBytes(values.traffic_limit_gb || 0),
    expiry_at: formExpiryToUnix(values),
  };
}

export function gbToBytes(value: number): number {
  const gb = Number(value || 0);
  if (!Number.isFinite(gb) || gb <= 0) return 0;
  return Math.round(gb * 1024 ** 3);
}

export function bytesToGB(value: number): number {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return 0;
  return Number((bytes / 1024 ** 3).toFixed(2));
}

function expiryToForm(expiryAt: number): Pick<ClientValues, 'expiry_mode' | 'expiry_date'> {
  if (!expiryAt) return { expiry_mode: 'unlimited', expiry_date: '' };
  return { expiry_mode: 'custom', expiry_date: formatLocalDate(new Date(expiryAt * 1000)) };
}

function formExpiryToUnix(values: Pick<ClientValues, 'expiry_mode' | 'expiry_date'>): number {
  if (values.expiry_mode === 'unlimited') return 0;
  if (values.expiry_mode === '30d') return relativeExpiryUnix(30);
  if (values.expiry_mode === '90d') return relativeExpiryUnix(90);
  if (!values.expiry_date) return 0;
  const timestamp = Date.parse(`${values.expiry_date}T23:59:59`);
  return Number.isFinite(timestamp) ? Math.floor(timestamp / 1000) : 0;
}

function relativeExpiryUnix(days: number): number {
  return Math.floor(Date.now() / 1000) + days * 86400;
}

function formatLocalDate(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function trafficStatusLabel(status: string | undefined, text: (value: string) => string) {
  if (status === 'ok') return text('统计正常');
  if (status === 'cumulative_only') return text('仅显示累计');
  if (status === 'partial') return text('部分不可用');
  if (status === 'stale') return text('统计状态过期');
  if (status === 'unavailable') return text('统计接口不可用');
  if (status === 'unsupported') return text('当前 sing-box 二进制不支持实时统计');
  if (status === 'not_configured') return text('未配置对应核心节点');
  return text('等待采样');
}

export function generatedProtocolCredential(protocol?: string) {
  const credentialStyle = protocolCredentialStyle(protocol);
  if (credentialStyle === 'secret') return randomSecret(24);
  if (credentialStyle === 'hex32') return randomUUID().replace(/-/g, '');
  return randomUUID();
}

function normalizedProtocolCredential(value: unknown, protocol?: string) {
  const current = String(value || '').trim();
  return protocolCredentialMatches(current, protocol) ? current : generatedProtocolCredential(protocol);
}

function protocolCredentialMatches(value: string, protocol?: string) {
  if (!value) return false;
  const credentialStyle = protocolCredentialStyle(protocol);
  if (credentialStyle === 'uuid') return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
  if (credentialStyle === 'hex32') return /^[0-9a-f]{32}$/i.test(value);
  return /^[0-9a-f]{24}$/i.test(value);
}

function protocolCredentialStyle(protocol?: string) {
  const normalized = String(protocol || '').toLowerCase();
  if (normalized === 'hysteria2' || normalized === 'tuic' || normalized === 'shadowtls') return 'hex32';
  if (normalized === 'shadowsocks' || normalized === 'socks' || normalized === 'http') return 'secret';
  return 'uuid';
}

export function generatedClientCredentialValues(protocol?: string) {
  const type = inboundCredentialType(protocol || 'vless');
  if (type === 'credential_id_password') return { uuid: randomUUID(), credential_id: randomUUID(), password: randomSecret(24) };
  if (type === 'username_password') {
    const username = `user-${randomSecret(8)}`;
    return { uuid: username, credential_id: username, password: randomSecret(24) };
  }
  if (type === 'password') {
    const password = randomSecret(24);
    return { uuid: password, credential_id: '', password };
  }
  if (type === 'none') return { uuid: randomSecret(24), credential_id: '', password: '' };
  const uuid = randomUUID();
  return { uuid, credential_id: uuid, password: '' };
}

function emptyClientCredentialValues() {
  return { uuid: '', credential_id: '', password: '' };
}

function randomHex(bytes: number) {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, '0')).join('');
}

function randomSecret(length: number) {
  return randomUUID().replace(/-/g, '').slice(0, length);
}

async function copyText(value: string, title: string, showToast: (title: string, tone?: 'success' | 'error' | 'info') => void, text?: (value: string) => string) {
  try {
    await copyToClipboard(value);
    showToast(title, 'success');
  } catch {
    showToast(text ? text('复制失败') : '复制失败', 'error');
  }
}

async function copyNodeLink(client: Client, showToast: (title: string, tone?: 'success' | 'error' | 'info') => void, text: (value: string) => string) {
  try {
    await copyText(await fetchNodeLink(client), text('节点链接已复制'), showToast, text);
  } catch {
    showToast(text('复制节点链接失败'), 'error');
  }
}

function shareToken(client: Client) {
  return client.subscription_token || client.uuid;
}

async function fetchNodeLink(client: Client) {
  return api.subscriptionLink(shareToken(client));
}

async function showClientQRCode(
  client: Client,
  showToast: (title: string, tone?: 'success' | 'error' | 'info') => void,
  setQRLink: (value: { title: string; value: string; dataURL: string }) => void,
  text: (value: string) => string,
) {
  try {
    const value = await fetchNodeLink(client);
    const dataURL = await QRCode.toDataURL(value, { margin: 1, width: 240 });
    setQRLink({ title: client.email || '', value, dataURL });
  } catch {
    showToast(text('生成二维码失败'), 'error');
  }
}

function errorMessage(error: unknown, fallback: string) {
  return getAPIErrorMessage(error, fallback);
}
