import { describe, expect, it } from 'vitest';
import type { Outbound, OutboundSubscription } from '../api/types';
import { outboundSupportedCores, outboundSupportLevel, outboundSupportLevelLabel } from '../lib/cores';
import { customOutboundIds, defaultOutboundSubscriptionUpdateIntervalSeconds, emptySubscription, formatSubscriptionPreview, isFixedDefaultOutbound, isReorderableOutbound, movedCustomOutboundIds, movedSubscriptionIds, outboundCredentialFields, outboundEnableDisabledReason, outboundFormValues, outboundMetaParts, outboundPasswordLabel, outboundRemarkLabel, outboundToggleTitle, outboundUsernameLabel, sanitizeOutboundValues, subscriptionDisplayName, subscriptionFormValues, subscriptionMetaParts, subscriptionOutboundUpdatePayload, subscriptionSourceLabel } from './OutboundsPage';

describe('outbound helpers', () => {
  const outbounds: Outbound[] = [
    { id: 1, tag: 'direct', protocol: 'freedom', enabled: true },
    { id: 2, tag: 'blocked', protocol: 'blackhole', enabled: true },
    { id: 9, tag: 'proxy-a', protocol: 'socks', address: '127.0.0.1', port: 1080, enabled: true },
    { id: 10, tag: 'proxy-b', protocol: 'http', address: '127.0.0.2', port: 8080, enabled: true },
    { id: 11, tag: 'custom-direct', protocol: 'freedom', enabled: true },
    { id: 12, tag: 'sub-a', protocol: 'trojan', enabled: true, source: 'subscription', subscription_id: 7 },
  ];

  it('keeps non-reorderable protocols out of reorder payloads', () => {
    expect(customOutboundIds(outbounds)).toEqual([9, 10]);
    expect(movedCustomOutboundIds(outbounds.filter(isReorderableOutbound), 1, -1)).toEqual([10, 9]);
  });

  it('only marks direct and blocked tags as fixed defaults', () => {
    expect(isFixedDefaultOutbound(outbounds[0])).toBe(true);
    expect(isFixedDefaultOutbound(outbounds[1])).toBe(true);
    expect(isFixedDefaultOutbound(outbounds[2])).toBe(false);
    expect(isFixedDefaultOutbound(outbounds[4])).toBe(false);
    expect(isFixedDefaultOutbound({ id: 12, tag: 'direct', protocol: 'socks', enabled: true })).toBe(false);
    expect(isFixedDefaultOutbound({ id: 13, tag: 'blocked', protocol: 'http', enabled: true })).toBe(false);
    expect(isReorderableOutbound(outbounds[4])).toBe(false);
    expect(isReorderableOutbound(outbounds[5])).toBe(false);
  });

  it('localizes built-in outbound remarks only', () => {
    const text = (value: string) => ({ 直接连接: 'Direct connection', 阻断: 'Blocked' })[value] || value;

    expect(outboundRemarkLabel('直接连接', text)).toBe('Direct connection');
    expect(outboundRemarkLabel('阻断', text)).toBe('Blocked');
    expect(outboundRemarkLabel('HK proxy', text)).toBe('HK proxy');
  });

  it('shows imported pool country details in outbound card metadata', () => {
    const text = (value: string) => value;

    expect(outboundMetaParts({
      protocol: 'http',
      address: '205.178.136.32',
      port: 8447,
      remark: 'Jacksonville AS19871 Web.com Group, Inc.',
    }, text, { country: 'United States', country_code: 'US' })).toEqual([
      'http',
      '205.178.136.32:8447',
      '国家/地区：United States',
      '备注：Jacksonville AS19871 Web.com Group, Inc.',
    ]);
  });

  it('derives outbound edit form values from the persisted outbound', () => {
    expect(outboundFormValues({
      id: 9,
      tag: 'proxy-a',
      remark: 'Proxy A',
      protocol: 'socks',
      address: '127.0.0.1',
      port: 1080,
      username: 'sam',
      password: 'secret',
      enabled: true,
    })).toMatchObject({
      tag: 'proxy-a',
      remark: 'Proxy A',
      protocol: 'socks',
      address: '127.0.0.1',
      port: 1080,
      username: 'sam',
      password: 'secret',
      enabled: true,
    });
  });

  it('labels constrained outbound credential fields by protocol', () => {
    expect(outboundUsernameLabel('shadowsocks')).toBe('Shadowsocks 加密方法');
    expect(outboundPasswordLabel('shadowtls')).toBe('ShadowTLS 密码');
    expect(outboundUsernameLabel('tuic')).toBe('UUID');
    expect(outboundUsernameLabel('vless')).toBe('UUID');
    expect(outboundPasswordLabel('vless')).toBe('密码');
  });

  it('derives credential field visibility by protocol', () => {
    expect(outboundCredentialFields('vless')).toEqual({ username: true, password: false });
    expect(outboundCredentialFields('tuic')).toEqual({ username: true, password: true });
    expect(outboundCredentialFields('shadowsocks')).toEqual({ username: true, password: true });
    expect(outboundCredentialFields('trojan')).toEqual({ username: false, password: true });
    expect(outboundCredentialFields('hysteria2')).toEqual({ username: false, password: true });
    expect(outboundCredentialFields('shadowtls')).toEqual({ username: false, password: true });
    expect(outboundCredentialFields('socks')).toEqual({ username: true, password: true });
  });

  it('derives outbound support level labels', () => {
    expect(outboundSupportLevelLabel('builtin')).toBe('内置');
    expect(outboundSupportLevelLabel('full')).toBe('完整');
    expect(outboundSupportLevelLabel('basic')).toBe('基础');
  });

  it('keeps outbound core support and support level aligned with backend protocol matrix', () => {
    const cases = [
      ['freedom', 'builtin', ['xray', 'sing-box']],
      ['blackhole', 'builtin', ['xray', 'sing-box']],
      ['dns', 'builtin', ['xray', 'sing-box']],
      ['direct', 'builtin', ['xray', 'sing-box']],
      ['block', 'builtin', ['xray', 'sing-box']],
      ['socks', 'full', ['xray', 'sing-box']],
      ['socks5', 'full', ['xray', 'sing-box']],
      ['http', 'full', ['xray', 'sing-box']],
      ['https', 'full', ['xray', 'sing-box']],
      ['vless', 'basic', ['xray', 'sing-box']],
      ['trojan', 'basic', ['xray', 'sing-box']],
      ['shadowsocks', 'basic', ['xray', 'sing-box']],
      ['hysteria2', 'basic', ['sing-box']],
      ['tuic', 'basic', ['sing-box']],
      ['shadowtls', 'basic', ['sing-box']],
      ['unknown', 'none', []],
    ] as const;
    cases.forEach(([protocol, level, cores]) => {
      expect(outboundSupportLevel({ protocol })).toBe(level);
      expect(outboundSupportedCores({ protocol })).toEqual(cores);
    });
  });

  it('clears hidden credential fields before saving', () => {
    expect(sanitizeOutboundValues({ protocol: 'vless', username: '11111111-1111-4111-8111-111111111111', password: 'unused' })).toMatchObject({
      username: '11111111-1111-4111-8111-111111111111',
      password: '',
    });
    expect(sanitizeOutboundValues({ protocol: 'trojan', username: 'unused', password: 'secret' })).toMatchObject({
      username: '',
      password: 'secret',
    });
  });

  it('clears hidden connection fields for builtin outbound protocols', () => {
    expect(sanitizeOutboundValues({ protocol: 'freedom', address: '127.0.0.1', port: 1080, username: 'unused', password: 'unused' })).toMatchObject({
      address: '',
      port: 0,
      username: '',
      password: '',
    });
    expect(sanitizeOutboundValues({ protocol: 'socks', address: '127.0.0.1', port: 1080, username: 'sam', password: 'secret' })).toMatchObject({
      address: '127.0.0.1',
      port: 1080,
      username: 'sam',
      password: 'secret',
    });
  });

  it('builds outbound subscription defaults and reorder payloads', () => {
    const subs: OutboundSubscription[] = [
      { id: 1, remark: 'A', url: 'https://a.example/sub', tag_prefix: 'sub1-', update_interval_seconds: 600, enabled: true, allow_private: false, prepend: false, priority: 0 },
      { id: 2, remark: 'B', url: 'https://b.example/sub', tag_prefix: 'sub2-', update_interval_seconds: 600, enabled: true, allow_private: false, prepend: true, priority: 1 },
    ];
    expect(emptySubscription(subs)).toMatchObject({ tag_prefix: 'sub3-', update_interval_seconds: defaultOutboundSubscriptionUpdateIntervalSeconds, enabled: true, allow_private: false, prepend: false });
    expect(movedSubscriptionIds(subs, 1, -1)).toEqual([2, 1]);
    expect(subscriptionFormValues(subs[1])).toMatchObject({ remark: 'B', url: 'https://b.example/sub', tag_prefix: 'sub2-', prepend: true });
  });

  it('formats subscription preview with skipped entries', () => {
    const text = (value: string) => value;
    expect(formatSubscriptionPreview({ count: 2, skipped_count: 0, skipped: [] }, text)).toBe('成功解析 2 个，跳过 0 个');
    expect(formatSubscriptionPreview({
      count: 1,
      skipped_count: 1,
      skipped: [{ raw: 'vmess://x', protocol: 'vmess', reason: 'vmess links are not supported yet' }],
    }, text)).toContain('vmess：vmess links are not supported yet');
  });

  it('formats subscription status timestamps and errors', () => {
    const text = (value: string) => value;
    expect(subscriptionMetaParts({
      tag_prefix: 'sub1-',
      last_fetched_at: '2026-06-20T10:00:00Z',
      last_attempt_at: '2026-06-20T11:00:00Z',
      last_error: 'upstream failed',
    }, text)).toEqual([
      'sub1-',
      expect.stringContaining('上次成功拉取：'),
      expect.stringContaining('上次尝试：'),
      '最近错误：upstream failed',
    ]);
  });

  it('resolves subscription source labels and disabled toggle reasons', () => {
    const text = (value: string) => value;
    const subscription: OutboundSubscription = {
      id: 7,
      remark: '',
      url: 'https://sub.example.com/path/token',
      tag_prefix: 'sub1-',
      update_interval_seconds: 600,
      enabled: false,
      allow_private: false,
      prepend: false,
      priority: 0,
    };
    const item: Outbound = { id: 12, tag: 'sub-a', protocol: 'trojan', enabled: false, source: 'subscription', subscription_id: 7 };

    expect(subscriptionDisplayName(subscription)).toBe('sub.example.com');
    expect(subscriptionSourceLabel(item, subscription, text)).toBe('订阅：sub.example.com');
    expect(subscriptionSourceLabel({ ...item, subscription_id: 99 }, undefined, text)).toBe('订阅已删除/未知');
    expect(outboundEnableDisabledReason(item, subscription, text)).toBe('所属订阅已停用');
    expect(outboundEnableDisabledReason({ ...item, subscription_id: 99 }, undefined, text)).toBe('订阅已删除/未知');
    expect(outboundToggleTitle(item, subscription, text)).toBe('所属订阅已停用');
    expect(outboundEnableDisabledReason({ ...item, enabled: true }, subscription, text)).toBe('');
  });

  it('keeps subscription outbound connection fields out of edit payload changes', () => {
    const outbound: Outbound = {
      id: 12,
      tag: 'sub-a',
      remark: 'old',
      protocol: 'trojan',
      address: 'example.com',
      port: 443,
      password: 'pw',
      enabled: true,
      source: 'subscription',
      settings_json: '{"tls":true}',
    };
    expect(subscriptionOutboundUpdatePayload(outbound, {
      tag: 'changed',
      remark: 'new',
      protocol: 'socks',
      address: '127.0.0.1',
      port: 1080,
      username: 'sam',
      password: 'secret',
      enabled: false,
    })).toMatchObject({
      tag: 'sub-a',
      remark: 'new',
      protocol: 'trojan',
      address: 'example.com',
      port: 443,
      password: 'pw',
      enabled: false,
      settings_json: '{"tls":true}',
    });
  });
});
