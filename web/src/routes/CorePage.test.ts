import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, createElement, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfirmProvider, ToastProvider } from '../components/ui';
import { I18nProvider } from '../lib/i18n';
import CorePage, { configSyncReasonLabel, configSyncState, coreActionResult, coreDiagnosticActions, coreDiagnosticChecks, coreDiagnosticsSummary, coreHealthSummary, coreInstalledWithDiagnostics, coreListeningDiagnostics, corePortSummary, coreStatusMetrics, coreStatusRefetchInterval, coreUserSyncState, diagnosticSuggestionItems, diagnosticWarningLabel, formatDiagnosticAction, isCoreInstalled } from './CorePage';

const apiMock = vi.hoisted(() => ({
  xrayStatus: vi.fn(async () => ({ service: 'xray', status: 'running', installed: true, managed: true, version: 'Xray 26.3.27', commands_executed: [] })),
  xrayVersion: vi.fn(async () => ({ version: 'Xray 26.3.27' })),
  xrayConfig: vi.fn(async () => ({})),
  xrayConfigPreview: vi.fn(async () => ({ config_path: '/etc/migate/cores/xray.json', in_sync: true })),
  xrayDiagnostics: vi.fn(async () => ({ installed: true, service_status: 'running', config_exists: true, config_valid: true, warnings: [] })),
  xrayLogs: vi.fn(async () => ({ logs: '' })),
  xrayValidate: vi.fn(async () => ({ target: 'xray', valid: true })),
  xrayApply: vi.fn(async () => ({ status: 'applied' })),
  xrayInstall: vi.fn(async () => ({ core: 'xray', status: 'installed' })),
  xrayUninstall: vi.fn(async () => ({ core: 'xray', status: 'unmanaged' })),
  xrayDelete: vi.fn(async () => ({ core: 'xray', status: 'deleted' })),
  xrayRestart: vi.fn(async () => ({ core: 'xray', status: 'restarted', commands_executed: ['systemctl restart migate-xray'] })),
  xrayStop: vi.fn(async () => ({ core: 'xray', status: 'stopped', commands_executed: ['systemctl stop migate-xray'] })),
  singboxStatus: vi.fn(async () => ({ service: 'sing-box', status: 'running', installed: true, managed: true, version: 'sing-box version 1.13.13', commands_executed: [] })),
  singboxVersion: vi.fn(async () => ({ version: 'sing-box version 1.13.13' })),
  singboxConfig: vi.fn(async () => ({})),
  singboxConfigPreview: vi.fn(async () => ({ config_path: '/etc/migate/cores/sing-box.json', in_sync: true })),
  singboxDiagnostics: vi.fn(async () => ({ installed: true, service_status: 'running', config_exists: true, config_valid: true, warnings: [] })),
  singboxLogs: vi.fn(async () => ({ logs: '' })),
  singboxValidate: vi.fn(async () => ({ target: 'singbox', valid: true })),
  singboxApply: vi.fn(async () => ({ status: 'applied' })),
  singboxInstall: vi.fn(async () => ({ core: 'singbox', status: 'installed' })),
  singboxUninstall: vi.fn(async () => ({ core: 'singbox', status: 'unmanaged' })),
  singboxDelete: vi.fn(async () => ({ core: 'singbox', status: 'deleted' })),
  singboxRestart: vi.fn(async () => ({ core: 'singbox', status: 'restarted', commands_executed: ['systemctl restart migate-sing-box'] })),
  singboxStop: vi.fn(async () => ({ core: 'singbox', status: 'stopped', commands_executed: ['systemctl stop migate-sing-box'] })),
}));

vi.mock('../api/endpoints', () => ({
  api: apiMock,
}));

let root: Root | null = null;
let container: HTMLDivElement | null = null;

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  root = null;
  container?.remove();
  container = null;
  vi.clearAllMocks();
});

describe('core action result', () => {
  it('treats xray apply validation failures as business errors', () => {
    expect(coreActionResult({ status: 'failed', error: 'validation' }, 'Xray 配置已应用')).toMatchObject({
      ok: false,
      message: 'validation',
    });
    expect(coreActionResult({ status: 'failed', error: 'validation' }, 'Xray 配置已应用')).not.toHaveProperty('detail');
    expect(coreActionResult({ xray: { status: 'failed: validation' } }, 'Xray 配置已应用')).toEqual({
      ok: false,
      message: 'failed: validation',
    });
  });

  it('treats accepted async apply results as informational success', () => {
    expect(coreActionResult({ accepted: true, status: 'accepted', message: '已开始应用 Xray 配置', apply_job: { id: 'job-1', core: 'xray', status: 'queued' } }, 'Xray 配置已应用')).toEqual({
      ok: true,
      message: '已开始应用 Xray 配置',
      tone: 'info',
      detail: 'job:\njob-1',
    });
  });

  it('detects nested xray and sing-box failures from HTTP 200 bodies', () => {
    expect(coreActionResult({ xray: { applied: false, error: 'validation_failed', detail: 'invalid config', commands_executed: ['xray run -test'] } }, 'Xray 配置已应用')).toEqual({
      ok: false,
      message: 'validation_failed',
      detail: 'commands:\nxray run -test\n\ndetail:\ninvalid config',
    });
    expect(coreActionResult({ xray: { status: 'not_managed', error_output: 'service is not managed' } }, 'Xray 配置已应用')).toMatchObject({
      ok: false,
      message: 'service is not managed',
    });
    expect(coreActionResult({ singbox: { applied: false, reason: 'invalid config' } }, 'sing-box 配置已应用')).toMatchObject({
      ok: false,
      message: 'invalid config',
    });
  });

  it('ignores legacy sing-box not_needed results when xray applied successfully', () => {
    expect(coreActionResult({ xray: { applied: true }, singbox: { applied: false, reason: 'not_needed' } }, 'Xray 配置已应用')).toEqual({
      ok: true,
      message: 'Xray 配置已应用',
    });
    expect(coreActionResult({ xray: { applied: false, error: 'validation_failed' }, singbox: { applied: false, reason: 'not_needed' } }, 'Xray 配置已应用')).toMatchObject({
      ok: false,
      message: 'validation_failed',
    });
    expect(coreActionResult({ xray: { applied: true }, singbox: { applied: false, reason: 'invalid config' } }, 'Xray 配置已应用')).toMatchObject({
      ok: false,
      message: 'invalid config',
    });
  });

  it('keeps command and error details for failed operations', () => {
    expect(coreActionResult({ xray: { status: 'failed', error_output: 'invalid json', commands_executed: ['xray -test'] } }, 'Xray 配置已应用')).toEqual({
      ok: false,
      message: 'invalid json',
      detail: 'commands:\nxray -test',
    });
  });

  it('keeps command details for successful applied operations', () => {
    expect(coreActionResult({ applied: true, commands_executed: ['sing-box check'], output: 'ok' }, 'sing-box 配置已应用')).toEqual({
      ok: true,
      message: 'sing-box 配置已应用',
      detail: 'commands:\nsing-box check\n\ndetail:\nok',
    });
    expect(coreActionResult({ singbox: { applied: true, commands_executed: ['sing-box check -c /etc/migate/cores/sing-box.json'], output: 'ok' } }, 'sing-box 配置已应用')).toEqual({
      ok: true,
      message: 'sing-box 配置已应用',
      detail: 'commands:\nsing-box check -c /etc/migate/cores/sing-box.json\n\ndetail:\nok',
    });
    expect(coreActionResult({ commands_executed: [], singbox: { applied: true, commands_executed: ['sing-box reload'], output: 'ok' } }, 'sing-box 配置已应用')).toEqual({
      ok: true,
      message: 'sing-box 配置已应用',
      detail: 'commands:\nsing-box reload\n\ndetail:\nok',
    });
  });

  it('surfaces post-apply listener warnings without marking apply as failed', () => {
    expect(coreActionResult({ singbox: { applied: true, post_apply_warnings: ['配置已应用，但端口未监听：21000/udp'] } }, 'sing-box 配置已应用')).toEqual({
      ok: true,
      message: '配置已应用，但端口未监听：21000/udp',
      tone: 'info',
    });
    expect(coreActionResult({ applied: true, post_apply_warnings: ['配置已应用，但端口未监听：21000/udp'] }, 'sing-box 配置已应用')).toEqual({
      ok: true,
      message: '配置已应用，但端口未监听：21000/udp',
      tone: 'info',
    });
    expect(coreActionResult({ applied: true, warnings: ['singbox_stats_unsupported'], singbox: { applied: true, post_apply_warnings: ['配置已应用，但端口未监听：21001/udp'] } }, 'sing-box 配置已应用')).toEqual({
      ok: true,
      message: '配置已应用，但端口未监听：21001/udp',
      tone: 'info',
    });
    expect(coreActionResult({ xray: { applied: true, post_apply_warnings: ['配置已应用，但端口未监听：2443/tcp'] } }, 'Xray 配置已应用')).toEqual({
      ok: true,
      message: '配置已应用，但端口未监听：2443/tcp',
      tone: 'info',
    });
  });

  it('covers core apply result edge cases across nested cores', () => {
    expect(coreActionResult({ xray: { applied: true } }, 'Xray 配置已应用')).toEqual({
      ok: true,
      message: 'Xray 配置已应用',
    });
    expect(coreActionResult({ xray: { applied: true }, singbox: { applied: false, reason: 'not_needed' } }, 'Xray 配置已应用')).toEqual({
      ok: true,
      message: 'Xray 配置已应用',
    });
    expect(coreActionResult({ xray: { applied: true, post_apply_warnings: ['配置已应用，但端口未监听：2443/tcp'] } }, 'Xray 配置已应用')).toEqual({
      ok: true,
      message: '配置已应用，但端口未监听：2443/tcp',
      tone: 'info',
    });
    expect(coreActionResult({ xray: { applied: false, error: 'validation_failed' } }, 'Xray 配置已应用')).toMatchObject({
      ok: false,
      message: 'validation_failed',
    });
    expect(coreActionResult({ singbox: { applied: false, reason: 'restart_failed' } }, 'sing-box 配置已应用')).toMatchObject({
      ok: false,
      message: 'restart_failed',
    });
    expect(coreActionResult({ applied: false, xray: { applied: true } }, 'Xray 配置已应用')).toEqual({
      ok: true,
      message: 'Xray 配置已应用',
    });
    expect(coreActionResult({ applied: false, error: 'apply_failed' }, 'sing-box 配置已应用')).toMatchObject({
      ok: false,
      message: 'apply_failed',
    });
  });

  it('pauses core status polling while the page is hidden', () => {
    expect(coreStatusRefetchInterval(true)).toBe(12000);
    expect(coreStatusRefetchInterval(false)).toBe(false);
  });

  it('derives installed state from explicit status first, then version/status fallbacks', () => {
    expect(isCoreInstalled({ installed: false, version: 'Xray 25.6.8', status: 'running' })).toBe(false);
    expect(isCoreInstalled({ version: 'sing-box version 1.13.13' })).toBe(true);
    expect(isCoreInstalled({ version: 'not_installed', status: 'not_installed' })).toBe(false);
    expect(isCoreInstalled(undefined)).toBe(false);
  });

  it('formats sing-box managed status and config path for core metrics', () => {
    const metrics = coreStatusMetrics({
      service: 'sing-box',
      installed: true,
      managed: true,
      status: 'running',
      version: 'sing-box version 1.13.13',
      config_path: '/etc/migate/cores/sing-box.json',
      active_connections: 0,
    });
    expect(metrics).toEqual(expect.arrayContaining([
      { label: '托管', value: '已托管' },
      { label: '配置路径', value: '/etc/migate/cores/sing-box.json' },
    ]));
  });

  it('formats core port listening diagnostics', () => {
    expect(coreListeningDiagnostics({
      service: 'sing-box',
      status: 'running',
      listening_ports: [
        { inbound_id: 9, protocol: 'hysteria2', port: 21001, network: 'udp', listening: false },
      ],
    })).toEqual([
      { inboundId: 9, protocol: 'hysteria2', port: 21001, transport: 'udp', listening: false },
    ]);
    expect(coreListeningDiagnostics({
      service: 'xray',
      status: 'running',
      listening_ports: [
        { inbound_id: 10, protocol: 'vless', port: 2443, network: 'grpc', transport: 'tcp', security: 'reality', grpc_service_name: 'svc', listening: true },
      ],
    })).toEqual([
      { inboundId: 10, protocol: 'vless', port: 2443, network: 'grpc', transport: 'tcp', security: 'reality', detail: 'svc', listening: true },
    ]);
  });

  it('summarizes sing-box generated and disk config sync state', () => {
    expect(configSyncState({ config_path: '/etc/migate/cores/sing-box.json', in_sync: true, disk: { config_path: '', hash: 'abc' }, generated: { config_path: '', hash: 'abc' } })).toMatchObject({
      ok: true,
      label: '磁盘配置与数据库生成配置一致',
    });
    expect(configSyncState({ config_path: '/etc/migate/cores/sing-box.json', in_sync: false, reason: 'hash_mismatch', disk: { config_path: '', hash: 'old' }, generated: { config_path: '', hash: 'new' } })).toMatchObject({
      ok: false,
      label: '磁盘配置与数据库生成配置不一致',
      detail: '原因：配置 hash 不一致 · disk: old · generated: new',
    });
    expect(configSyncReasonLabel('disk_parse_failed')).toBe('磁盘配置解析失败');
    expect(configSyncState(undefined, false, new Error('preview failed'))).toEqual({
      ok: false,
      label: '生成配置预览失败',
      detail: 'preview failed',
    });
  });

  it('summarizes core diagnostics and critical checks', () => {
    const diagnostics = {
      installed: true,
      managed: true,
      service: 'sing-box',
      service_status: 'running',
      config_path: '/etc/migate/cores/sing-box.json',
      config_exists: true,
      config_valid: true,
      disk_generated_in_sync: false,
      sync_reason: 'hash_mismatch',
      expected_listeners: [{ inbound_id: 9, protocol: 'hysteria2', port: 21001, transport: 'udp', listening: false }],
      missing_listeners: [{ inbound_id: 9, protocol: 'hysteria2', port: 21001, transport: 'udp', listening: false }],
      recent_logs: ['line 1', 'line 2'],
      warnings: ['singbox_missing_listeners'],
      suggestions: ['查看日志'],
    };
    expect(coreDiagnosticsSummary(diagnostics)).toEqual({
      tone: 'warning',
      label: '警告',
      detail: 'singbox_missing_listeners',
    });
    expect(coreDiagnosticChecks(diagnostics)).toEqual(expect.arrayContaining([
      { label: '配置同步', value: '配置 hash 不一致', ok: false },
      { label: '端口监听', value: '缺失 1 个', ok: false },
    ]));
    expect(diagnosticWarningLabel('singbox_missing_listeners')).toBe('服务运行但入站端口未监听');
    expect(diagnosticWarningLabel('xray_missing_listeners')).toBe('服务运行但入站端口未监听');
    expect(diagnosticWarningLabel('xray_config_invalid')).toBe('xray run -test 失败');
    expect(diagnosticWarningLabel('xray_ws_path_invalid')).toBe('WS/H2 path 配置无效');
    expect(diagnosticWarningLabel('xray_grpc_service_name_invalid')).toBe('gRPC serviceName 配置无效');
    expect(diagnosticWarningLabel('xray_xhttp_path_invalid')).toBe('XHTTP path 配置无效');
    expect(diagnosticWarningLabel('xray_reality_settings_incomplete')).toBe('REALITY 配置不完整');
    expect(diagnosticWarningLabel('xray_tls_certificate_missing')).toBe('TLS 证书配置缺失');
    expect(diagnosticWarningLabel('xray_shadowsocks_credentials_missing')).toBe('Shadowsocks 2022 缺少可用凭据');
    expect(diagnosticWarningLabel('unknown_warning')).toBe('unknown_warning');
  });

  it('derives a user-facing core health summary from status, sync and listeners', () => {
    expect(coreHealthSummary(
      { service: 'xray', status: 'not_installed', installed: false },
      { installed: true, managed: true, service: 'xray', service_status: 'running', config_path: '/etc/migate/cores/xray.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [], recent_logs: [], warnings: [], suggestions: [] },
    )).toMatchObject({
      tone: 'error',
      headline: '核心未安装',
      nextAction: '先安装核心，再应用配置。',
    });
    expect(coreInstalledWithDiagnostics(
      { service: 'xray', status: 'not_installed', installed: false },
      { installed: true, managed: true, service: 'xray', service_status: 'running', config_path: '/etc/migate/cores/xray.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [], recent_logs: [], warnings: [], suggestions: [] },
    )).toBe(false);
    expect(coreInstalledWithDiagnostics(
      { service: 'xray', status: 'not_installed' },
      { installed: true, managed: true, service: 'xray', service_status: 'running', config_path: '/etc/migate/cores/xray.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [], recent_logs: [], warnings: [], suggestions: [] },
    )).toBe(false);
    expect(coreInstalledWithDiagnostics(
      { service: 'xray', status: 'unknown', version: 'not_installed' },
      { installed: true, managed: true, service: 'xray', service_status: 'running', config_path: '/etc/migate/cores/xray.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [], recent_logs: [], warnings: [], suggestions: [] },
    )).toBe(false);
    expect(coreInstalledWithDiagnostics(
      { service: 'xray', status: 'unknown', version: 'unknown' },
      { installed: true, managed: true, service: 'xray', service_status: 'running', config_path: '/etc/migate/cores/xray.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [], recent_logs: [], warnings: [], suggestions: [] },
    )).toBe(true);

    expect(coreHealthSummary(
      { service: 'sing-box', status: 'running', installed: true, managed: true, listening_ports: [{ inbound_id: 9, protocol: 'hysteria2', port: 21001, transport: 'udp', listening: false }] },
      { installed: true, managed: true, service: 'sing-box', service_status: 'running', config_path: '/etc/migate/cores/sing-box.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [{ inbound_id: 9, protocol: 'hysteria2', port: 21001, transport: 'udp', listening: false }], recent_logs: [], warnings: ['singbox_missing_listeners'], suggestions: [] },
      { config_path: '/etc/migate/cores/sing-box.json', in_sync: true, disk: { config_path: '', hash: 'a' }, generated: { config_path: '', hash: 'a' } },
    )).toMatchObject({
      tone: 'warning',
      headline: '存在未监听端口',
      detail: '有 1 个入站端口未监听。',
    });

    expect(coreHealthSummary(
      { service: 'xray', status: 'running', installed: true, managed: true },
      { installed: true, managed: true, service: 'xray', service_status: 'running', config_path: '/etc/migate/cores/xray.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [], recent_logs: [], warnings: [], suggestions: [] },
      { config_path: '/etc/migate/cores/xray.json', in_sync: true, disk: { config_path: '', hash: 'a' }, generated: { config_path: '', hash: 'a' } },
    )).toMatchObject({
      tone: 'ok',
      headline: '核心运行正常',
    });
  });

  it('derives human core sync states for the core page', () => {
    expect(coreUserSyncState(
      { service: 'xray', status: 'running', apply_job: { id: 'job-1', core: 'xray', status: 'retrying', retry_count: 1, max_retries: 3 } },
      undefined,
      { config_path: '/etc/migate/cores/xray.json', in_sync: false, pending_apply: true, disk: { config_path: '' }, generated: { config_path: '' } },
    )).toMatchObject({
      key: 'syncing',
      label: '正在同步',
      detail: '自动重试中，第 1/3 次重试。完成后会自动更新状态。',
    });
    expect(coreUserSyncState(
      { service: 'xray', status: 'running', apply_job: { id: 'job-1', core: 'xray', status: 'failed', detail: 'bad config' } },
    )).toMatchObject({
      key: 'failed',
      label: '同步失败',
      action: '可点击“重试同步”，或查看高级详情定位问题。',
    });
    expect(coreUserSyncState(
      { service: 'xray', status: 'running' },
      { installed: true, managed: true, service: 'xray', service_status: 'running', config_path: '/etc/migate/cores/xray.json', config_exists: true, config_valid: true, disk_generated_in_sync: true, expected_listeners: [], missing_listeners: [], recent_logs: [], warnings: [], suggestions: [] },
      { config_path: '/etc/migate/cores/xray.json', in_sync: true, disk: { config_path: '', hash: 'a' }, generated: { config_path: '', hash: 'a' } },
    )).toMatchObject({
      key: 'in_sync',
      label: '已生效',
      action: '无需处理。',
    });
  });

  it('summarizes listening ports for the compact port section', () => {
    expect(corePortSummary([])).toBe('暂无监听端口数据。');
    expect(corePortSummary([{ inboundId: 1, protocol: 'vless', port: 443, transport: 'tcp', listening: true }])).toBe('1 个端口监听正常。');
    expect(corePortSummary([{ inboundId: 1, protocol: 'vless', port: 443, transport: 'tcp', listening: false }])).toBe('1 个端口未监听，请优先检查服务日志和防火墙。');
  });

  it('formats structured diagnostic actions before legacy suggestions', () => {
    const diagnostics = {
      installed: true,
      managed: true,
      service: 'xray',
      service_status: 'running',
      config_path: '/etc/migate/cores/xray.json',
      config_exists: true,
      config_valid: true,
      disk_generated_in_sync: true,
      expected_listeners: [],
      missing_listeners: [],
      recent_logs: [],
      warnings: ['xray_config_invalid'],
      suggestions: ['旧建议'],
      actions: [{
        code: 'xray_config_invalid',
        severity: 'error',
        category: 'config',
        message: '按校验报错修复后重新应用。',
        command: 'xray run -test -c /etc/migate/cores/xray.json',
        inbound_id: 7,
        port: 2443,
      }],
    };
    expect(coreDiagnosticActions(diagnostics)).toHaveLength(1);
    expect(formatDiagnosticAction(diagnostics.actions[0])).toEqual({
      severity: '错误',
      category: '配置',
      message: '按校验报错修复后重新应用。',
      command: 'xray run -test -c /etc/migate/cores/xray.json',
      target: '入站 7 · 端口 2443',
      summary: '错误 · 配置 · 入站 7 · 端口 2443 · 按校验报错修复后重新应用。 · 命令：xray run -test -c /etc/migate/cores/xray.json',
    });
    expect(diagnosticSuggestionItems(diagnostics)).toEqual([
      '错误 · 配置 · 入站 7 · 端口 2443 · 按校验报错修复后重新应用。 · 命令：xray run -test -c /etc/migate/cores/xray.json',
    ]);
  });

  it('falls back to legacy suggestions when structured actions are absent', () => {
    expect(diagnosticSuggestionItems({
      installed: true,
      managed: true,
      service: 'xray',
      service_status: 'running',
      config_path: '/etc/migate/cores/xray.json',
      config_exists: true,
      config_valid: true,
      disk_generated_in_sync: true,
      expected_listeners: [],
      missing_listeners: [],
      recent_logs: [],
      warnings: [],
      suggestions: ['查看日志'],
    })).toEqual(['查看日志']);
  });
});

describe('core service controls', () => {
  it('renders the redesigned Xray operations layout with summary, sync, ports, diagnostics and collapsed logs', async () => {
    apiMock.xrayStatus.mockResolvedValueOnce({
      service: 'xray',
      status: 'running',
      installed: true,
      managed: true,
      version: 'Xray 26.3.27',
      config_path: '/etc/migate/cores/xray.json',
      active_connections: 3,
      listening_ports: [
        { inbound_id: 10, protocol: 'vless', port: 2443, network: 'grpc', transport: 'tcp', security: 'reality', grpc_service_name: 'svc', listening: true },
      ],
      commands_executed: [],
    } as Awaited<ReturnType<typeof apiMock.xrayStatus>>);
    apiMock.xrayConfigPreview.mockResolvedValueOnce({
      config_path: '/etc/migate/cores/xray.json',
      in_sync: false,
      reason: 'hash_mismatch',
      disk: { config_path: '/etc/migate/cores/xray.json', hash: 'old' },
      generated: { config_path: '/etc/migate/cores/xray.json', hash: 'new' },
    } as Awaited<ReturnType<typeof apiMock.xrayConfigPreview>>);
    apiMock.xrayDiagnostics.mockResolvedValueOnce({
      installed: true,
      managed: true,
      service: 'xray',
      service_status: 'running',
      config_path: '/etc/migate/cores/xray.json',
      config_exists: true,
      config_valid: true,
      disk_generated_in_sync: false,
      sync_reason: 'hash_mismatch',
      expected_listeners: [],
      missing_listeners: [],
      recent_logs: [],
      warnings: ['xray_config_out_of_sync'],
      suggestions: ['点击应用重新写入 Xray 配置。'],
      actions: [{ code: 'xray_config_out_of_sync', severity: 'warning', category: 'config', message: '点击应用重新写入 Xray 配置。' }],
    } as unknown as Awaited<ReturnType<typeof apiMock.xrayDiagnostics>>);

    renderCorePage('xray');
    await waitForText('Xray 核心管理');
    await waitForText('配置不同步');
    expect(document.body.textContent).toContain('主操作');
    expect(document.body.textContent).toContain('重新同步');
    expect(document.body.textContent).toContain('配置状态');
    expect(document.body.textContent).toContain('/etc/migate/cores/xray.json');
    expect(document.body.textContent).toContain('监听端口');
    expect(document.body.textContent).toContain('svc');
    expect(document.body.textContent).not.toContain('最近日志');

    await clickButtonByText('高级详情');
    await waitForText('诊断');
    expect(document.body.textContent).toContain('推荐操作');
    expect(document.body.textContent).toContain('最近日志');
  });

  it('renders sing-box port issues and apply results in the redesigned panel', async () => {
    apiMock.singboxStatus.mockResolvedValueOnce({
      service: 'sing-box',
      status: 'running',
      installed: true,
      managed: true,
      version: 'sing-box version 1.13.13',
      config_path: '/etc/migate/cores/sing-box.json',
      listening_ports: [
        { inbound_id: 9, protocol: 'hysteria2', port: 21001, network: 'udp', transport: 'udp', listening: false },
      ],
      commands_executed: [],
    } as Awaited<ReturnType<typeof apiMock.singboxStatus>>);
    apiMock.singboxDiagnostics.mockResolvedValueOnce({
      installed: true,
      managed: true,
      service: 'sing-box',
      service_status: 'running',
      config_path: '/etc/migate/cores/sing-box.json',
      config_exists: true,
      config_valid: true,
      disk_generated_in_sync: true,
      expected_listeners: [],
      missing_listeners: [{ inbound_id: 9, protocol: 'hysteria2', port: 21001, network: 'udp', transport: 'udp', listening: false }],
      recent_logs: ['listen udp :21001: bind: address already in use'],
      warnings: ['singbox_missing_listeners'],
      suggestions: [],
      actions: [{ code: 'singbox_missing_listeners', severity: 'warning', category: 'listener', message: '检查防火墙/安全组是否放行 UDP 端口 21001。', port: 21001 }],
    } as unknown as Awaited<ReturnType<typeof apiMock.singboxDiagnostics>>);
    apiMock.singboxApply.mockResolvedValueOnce({ applied: true, commands_executed: ['sing-box check'], post_apply_warnings: ['配置已应用，但端口未监听：21001/udp'] } as unknown as Awaited<ReturnType<typeof apiMock.singboxApply>>);

    renderCorePage('singbox');
    await waitForText('Sing-box 核心管理');
    await waitForText('存在未监听端口');
    expect(document.body.textContent).toContain('21001');
    expect(document.body.textContent).not.toContain('检查防火墙/安全组是否放行 UDP 端口 21001。');

    await clickButtonByText('高级详情');
    await waitForText('检查防火墙/安全组是否放行 UDP 端口 21001。');
    await clickButtonByText('重新同步');
    await clickButtonByText('确认');
    await vi.waitFor(() => expect(apiMock.singboxApply).toHaveBeenCalledTimes(1));
    await waitForText('配置已应用，但端口未监听：21001/udp');
  });

  it('keeps retrying apply jobs visible as in-progress on the core page', async () => {
    apiMock.xrayStatus.mockResolvedValueOnce({
      service: 'xray',
      status: 'running',
      installed: true,
      managed: true,
      version: 'Xray 26.3.27',
      config_path: '/etc/migate/cores/xray.json',
      apply_job: { id: 'job-1', core: 'xray', status: 'retrying', retry_count: 1, max_retries: 3 },
      commands_executed: [],
    } as Awaited<ReturnType<typeof apiMock.xrayStatus>>);

    renderCorePage('xray');
    await waitForText('正在同步核心配置');
    expect(document.body.textContent).toContain('应用进行中：自动重试中');
    expect(document.body.textContent).toContain('第 1/3 次重试');
  });

  it('uses diagnostics installed state for operation controls when status is unknown', async () => {
    apiMock.xrayStatus.mockResolvedValueOnce({
      service: 'xray',
      status: 'unknown',
      version: 'unknown',
      managed: true,
      commands_executed: [],
    } as Awaited<ReturnType<typeof apiMock.xrayStatus>>);
    apiMock.xrayDiagnostics.mockResolvedValueOnce({
      installed: true,
      managed: true,
      service: 'xray',
      service_status: 'running',
      config_path: '/etc/migate/cores/xray.json',
      config_exists: true,
      config_valid: true,
      disk_generated_in_sync: true,
      expected_listeners: [],
      missing_listeners: [],
      recent_logs: [],
      warnings: [],
      suggestions: [],
    } as unknown as Awaited<ReturnType<typeof apiMock.xrayDiagnostics>>);

    renderCorePage('xray');
    await waitForText('高级维护');
    await clickButtonByText('高级维护');
    await waitForText('升级/重装核心');
    await clickButtonByText('重启核心');
    await clickButtonByText('确认');
    await vi.waitFor(() => expect(apiMock.xrayRestart).toHaveBeenCalledTimes(1));
  });

  it('keeps healthy diagnostics compact and avoids rendering an empty port table', async () => {
    apiMock.xrayStatus.mockResolvedValueOnce({
      service: 'xray',
      status: 'running',
      installed: true,
      managed: true,
      version: 'Xray 26.3.27',
      config_path: '/etc/migate/cores/xray.json',
      listening_ports: [],
      commands_executed: [],
    } as Awaited<ReturnType<typeof apiMock.xrayStatus>>);
    apiMock.xrayDiagnostics.mockResolvedValueOnce({
      installed: true,
      managed: true,
      service: 'xray',
      service_status: 'running',
      config_path: '/etc/migate/cores/xray.json',
      config_exists: true,
      config_valid: true,
      disk_generated_in_sync: true,
      expected_listeners: [],
      missing_listeners: [],
      recent_logs: [],
      warnings: [],
      suggestions: [],
    } as unknown as Awaited<ReturnType<typeof apiMock.xrayDiagnostics>>);

    renderCorePage('xray');
    await waitForText('当前没有可展示的监听端口。');
    expect(document.body.textContent).not.toContain('未发现需要处理的问题');

    expect(document.querySelector('.core-port-table')).toBeNull();
    expect(document.querySelector('.core-diagnostics-card')).toBeNull();
  });

  it('renders and calls Xray restart and advanced stop actions after confirmation', async () => {
    renderCorePage('xray');
    await waitForText('重启核心');
    expect(document.body.textContent).not.toContain('停止核心');

    await clickButtonByText('重启核心');
    await clickButtonByText('确认');
    await vi.waitFor(() => expect(apiMock.xrayRestart).toHaveBeenCalledTimes(1));

    await clickButtonByText('高级维护');
    await waitForText('停止核心');
    await clickButtonByText('停止核心');
    await clickButtonByText('确认');
    await vi.waitFor(() => expect(apiMock.xrayStop).toHaveBeenCalledTimes(1));
  });

  it('renders and calls sing-box restart and advanced stop actions after confirmation', async () => {
    renderCorePage('singbox');
    await waitForText('重启核心');
    expect(document.body.textContent).not.toContain('停止核心');

    await clickButtonByText('重启核心');
    await clickButtonByText('确认');
    await vi.waitFor(() => expect(apiMock.singboxRestart).toHaveBeenCalledTimes(1));

    await clickButtonByText('高级维护');
    await waitForText('停止核心');
    await clickButtonByText('停止核心');
    await clickButtonByText('确认');
    await vi.waitFor(() => expect(apiMock.singboxStop).toHaveBeenCalledTimes(1));
  });
});

function renderCorePage(core: 'xray' | 'singbox') {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  renderNode(
    createElement(
      I18nProvider,
      null,
      createElement(
        QueryClientProvider,
        { client: queryClient },
        createElement(
          ToastProvider,
          null,
          createElement(
            ConfirmProvider,
            null,
            createElement(MemoryRouter, { initialEntries: [core === 'xray' ? '/core/xray' : '/core/singbox'] }, createElement(CorePage, { core })),
          ),
        ),
      ),
    ),
  );
}

function renderNode(node: ReactNode) {
  act(() => {
    root!.render(node);
  });
}

async function waitForText(text: string) {
  await vi.waitFor(() => expect(document.body.textContent).toContain(text));
}

async function clickButtonByText(text: string) {
  const button = await findEnabledButtonByText(text);
  act(() => button.click());
}

async function findEnabledButtonByText(text: string): Promise<HTMLButtonElement> {
  let found: HTMLButtonElement | undefined;
  await vi.waitFor(() => {
    found = Array.from(document.querySelectorAll('button')).find((item) => item.textContent?.includes(text)) as HTMLButtonElement | undefined;
    expect(found).toBeTruthy();
    expect(found!.disabled).toBe(false);
  });
  return found!;
}
