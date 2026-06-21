import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import { certificateInventorySummary, certificateStatusLabel, certIssuePayload, certSettingsPayload, formatUpdateLogs, hasTLSCertificateBinding, inboundCertificateBindingStatus, isUpdateInProgress, isUpdateTerminal, parseDomains, preflightFromAPIError, settingsPayload, shouldClearInboundSelectionForActualCertificate, shouldClearInboundSelectionOnCertificateSelect, toggleID, updateAvailabilitySummary, updateDependencyRefetchInterval, updatePrimaryAction, updateStatusRefetchInterval, updateStatusSummaryKey } from './SettingsPage';

describe('settings helpers', () => {
  it('sends an empty password to preserve the existing backend password', () => {
    expect(settingsPayload({
      panel_username: 'admin',
      panel_password: undefined,
      management_direct_hosts: ['panel.example.com'],
      management_direct_ports: [22, 9999],
    }, { panel_port: 9999, panel_password: '' })).toMatchObject({
      panel_username: 'admin',
      panel_port: 9999,
      panel_password: '',
      management_direct_hosts: ['panel.example.com'],
      management_direct_ports: [22, 9999],
    });
  });

  it('keeps invalid management ports visible to backend validation', () => {
    expect(settingsPayload(undefined, { management_direct_ports: '22, 9999' })).toMatchObject({
      management_direct_ports: [22, 9999],
    });
    for (const value of ['22, 70000, abc', '1e3', '0x16', '22.0']) {
      expect(settingsPayload(undefined, { management_direct_ports: value })).toMatchObject({
        management_direct_ports: value,
      });
    }
  });

  it('uses current form domain and email when issuing certificates', () => {
    expect(certIssuePayload({ cert_domain: 'new.example.com', cert_email: 'ops@example.com' }, { domain: 'old.example.com', email: 'old@example.com' })).toEqual({
      domain: 'new.example.com',
      email: 'ops@example.com',
    });
  });

  it('saves only certificate fields from the certificate card', () => {
    expect(certSettingsPayload(
      { panel_port: 9999, web_base_path: '/panel', cert_domain: 'old.example.com', cert_email: 'old@example.com' },
      { panel_port: 7777, web_base_path: '/draft', cert_domain: 'new.example.com', cert_email: 'ops@example.com', panel_password: 'draft' },
    )).toMatchObject({
      panel_port: 9999,
      web_base_path: '/panel',
      cert_domain: 'new.example.com',
      cert_email: 'ops@example.com',
      panel_password: '',
    });
  });

  it('polls update status only while an update is active', () => {
    expect(isUpdateInProgress('updating')).toBe(true);
    expect(isUpdateInProgress('installing')).toBe(true);
    expect(isUpdateInProgress('restarting')).toBe(true);
    expect(isUpdateInProgress('idle')).toBe(false);
    expect(updateStatusRefetchInterval('updating')).toBe(5000);
    expect(updateStatusRefetchInterval('idle', true)).toBe(5000);
    expect(updateDependencyRefetchInterval(true)).toBe(5000);
    expect(updateDependencyRefetchInterval(false)).toBe(false);
    expect(updateStatusRefetchInterval('completed')).toBe(false);
    expect(updateStatusRefetchInterval(undefined)).toBe(false);
    expect(isUpdateTerminal('failed')).toBe(true);
    expect(isUpdateTerminal('restarting')).toBe(false);
    expect(isUpdateTerminal('updating')).toBe(false);
  });

  it('summarizes update completion and rollback states', () => {
    expect(updateStatusSummaryKey({ status: 'completed' })).toBe('升级成功，服务已可用');
    expect(updateStatusSummaryKey({ status: 'failed', rolled_back: true, rollback_status: 'restored' })).toBe('升级失败，已回滚，服务已恢复');
    expect(updateStatusSummaryKey({ status: 'failed', rolled_back: true, rollback_status: 'failed' })).toBe('');
    expect(updatePrimaryAction({ update_available: false }, { status: 'idle' })).toBe('check');
    expect(updatePrimaryAction({ update_available: false }, undefined)).toBe('check');
    expect(updatePrimaryAction({ update_available: true }, { status: 'idle' })).toBe('update');
    expect(updatePrimaryAction({ update_available: false }, { status: 'installing' })).toBe('update');
    expect(updateAvailabilitySummary({ status: 'ok', message: '当前版本高于最新发布版本，不会执行默认升级' }, (value) => value)).toBe('当前版本高于最新发布版本，不会执行默认升级');
  });

  it('formats update logs from API responses', () => {
    expect(formatUpdateLogs(undefined, 'empty')).toBe('empty');
    expect(formatUpdateLogs({ lines: ['a', 'b'] }, 'empty')).toBe('a\nb');
    expect(formatUpdateLogs({ logs: 'raw log' }, 'empty')).toBe('raw log');
  });

  it('normalizes certificate domains and statuses', () => {
    expect(parseDomains('Example.com, www.example.com  example.com')).toEqual(['example.com', 'www.example.com']);
    expect(certificateStatusLabel('expiring_soon')).toBe('即将到期');
    expect(toggleID([1, 2], 2)).toEqual([1]);
    expect(toggleID([1], 2)).toEqual([1, 2]);
  });

  it('summarizes certificate inventory and recommended actions', () => {
    expect(certificateInventorySummary([], []).recommendedAction).toBe('暂无证书，建议先申请 ACME 证书。');
    expect(certificateInventorySummary([
      { id: 1, name: 'a', source: 'acme', status: 'issued', domains: ['a.test'], cert_path: '/cert', key_path: '/key', usage_count: 2 },
      { id: 2, name: 'b', source: 'acme', status: 'expiring_soon', domains: ['b.test'], cert_path: '/cert', key_path: '/key', usage_count: 0 },
    ], [{ id: 9, remark: 'tls', protocol: 'vless', port: 443, network: 'tcp', security: 'tls', enabled: true, tls_cert_file: '/cert', tls_key_file: '/key' }])).toMatchObject({
      total: 2,
      valid: 1,
      expiring: 1,
      boundInbounds: 1,
      usageCount: 2,
      recommendedAction: '存在即将到期证书，建议运行续期检查。',
    });
  });

  it('counts inbound TLS bindings only from tls_cert_file and tls_key_file', () => {
    expect(hasTLSCertificateBinding({ id: 1, remark: 'old', protocol: 'vless', port: 443, network: 'tcp', security: 'tls', enabled: true, cert_path: '/legacy' })).toBe(false);
    expect(hasTLSCertificateBinding({ id: 2, remark: 'empty', protocol: 'vless', port: 443, network: 'tcp', security: 'tls', enabled: true, tls_cert_file: '', tls_key_file: '' })).toBe(false);
    expect(hasTLSCertificateBinding({ id: 3, remark: 'bound', protocol: 'vless', port: 443, network: 'tcp', security: 'tls', enabled: true, tls_cert_file: '/cert', tls_key_file: '/key' })).toBe(true);
  });

  it('describes inbound certificate binding state against the selected certificate', () => {
    const certificate = { id: 1, name: 'a', source: 'acme', status: 'issued', domains: ['a.test'], cert_path: '/cert', key_path: '/key', usage_count: 1 };
    expect(inboundCertificateBindingStatus({ id: 1, remark: 'current', protocol: 'vless', port: 443, network: 'tcp', security: 'tls', enabled: true, tls_cert_file: '/cert', tls_key_file: '/key' }, certificate)).toBe('current');
    expect(inboundCertificateBindingStatus({ id: 2, remark: 'other', protocol: 'vless', port: 443, network: 'tcp', security: 'tls', enabled: true, tls_cert_file: '/other-cert', tls_key_file: '/other-key' }, certificate)).toBe('other');
    expect(inboundCertificateBindingStatus({ id: 3, remark: 'none', protocol: 'vless', port: 443, network: 'tcp', security: 'tls', enabled: true, tls_cert_file: '', tls_key_file: '' }, certificate)).toBe('none');
  });

  it('clears inbound selection when switching to another certificate', () => {
    expect(shouldClearInboundSelectionOnCertificateSelect(1, 2)).toBe(true);
    expect(shouldClearInboundSelectionOnCertificateSelect(1, 1)).toBe(false);
    expect(shouldClearInboundSelectionForActualCertificate(1, 2, 3)).toBe(true);
    expect(shouldClearInboundSelectionForActualCertificate(1, 1, 3)).toBe(false);
    expect(shouldClearInboundSelectionForActualCertificate(1, null, 3)).toBe(true);
    expect(shouldClearInboundSelectionForActualCertificate(null, 1, 3)).toBe(true);
    expect(shouldClearInboundSelectionForActualCertificate(1, 2, 0)).toBe(false);
  });

  it('extracts preflight checks from standard API error fields', () => {
    const preflight = { ok: false, checks: [{ code: 'http_01_port_unavailable', status: 'failed', detail: 'bind failed' }] };
    const error = new ApiError(409, 'preflight_failed', { error: { code: 'preflight_failed', fields: { preflight } } }, { code: 'preflight_failed', fields: { preflight } });
    expect(preflightFromAPIError(error)).toEqual(preflight);
    expect(preflightFromAPIError(new Error('legacy'))).toBeNull();
  });
});
