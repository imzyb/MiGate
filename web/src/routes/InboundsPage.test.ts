import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { Inbound, InboundCapability } from '../api/types';
import {
  allowedInboundNetworks,
  allowedInboundSecurities,
  applyInboundCapabilitiesFromAPI,
  applyInboundTemplate,
  buildClientPayload,
  buildFullInboundPayload,
  bytesToGB,
  clientFormValues,
  createDefaultInbound,
  enabledInboundAdvancedFields,
  gbToBytes,
  hasAttachableSettingCert,
  inboundCredentialType,
  inboundFormValues,
  inboundProtocolOptions,
  mergeInboundTraffic,
  resetInboundCapabilitiesForTest,
  sanitizeInboundFormValues,
  supportsInboundShareLink,
} from './InboundsPage';
import { savedClientLinkActions } from './InboundsPageForms';

afterEach(() => {
  resetInboundCapabilitiesForTest();
});

describe('inbounds page i18n coverage', () => {
  it('keeps primary page Chinese copy behind explicit text calls', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/routes/InboundsPage.tsx'), 'utf8');
    const forbidden = [
      /title="[^"]*[\u4e00-\u9fff]/,
      /description="[^"]*[\u4e00-\u9fff]/,
      /placeholder="[^"]*[\u4e00-\u9fff]/,
      /showToast\('[^']*[\u4e00-\u9fff]/,
      /<option[^>]*>[^<{]*[\u4e00-\u9fff]/,
      /<EmptyState\s+title="[^"]*[\u4e00-\u9fff]/,
    ];
    for (const pattern of forbidden) {
      expect(source).not.toMatch(pattern);
    }
  });
});

describe('inbound payload helpers', () => {
  const existing: Inbound = {
    id: 12,
    remark: 'edge',
    protocol: 'vless',
    port: 443,
    network: 'xhttp',
    security: 'reality',
    enabled: true,
    uuid: '11111111-1111-4111-8111-111111111111',
    clients: [],
    traffic_up: 100,
    traffic_down: 200,
    traffic_total: 300,
    rate_up: 1,
    rate_down: 2,
    traffic_status: 'ok',
    client_traffic: {},
    ws_path: '/ws',
    ws_host: 'cdn.example.com',
    grpc_service_name: 'grpc-edge',
    reality_dest: 'www.cloudflare.com:443',
    reality_server_names: 'www.cloudflare.com',
    reality_short_id: 'abcd',
    reality_private_key: 'private-key',
    reality_public_key: 'public-key',
    ss_method: '2022-blake3-aes-128-gcm',
    tls_cert_file: '/etc/migate/certs/example/fullchain.pem',
    tls_key_file: '/etc/migate/certs/example/privkey.pem',
    tls_sni: 'example.com',
    tls_fingerprint: 'chrome',
    tls_alpn: 'h2,http/1.1',
    xhttp_path: '/xhttp',
    xhttp_mode: 'stream-one',
    hy2_up_mbps: 100,
    hy2_down_mbps: 200,
    hy2_obfs: 'salamander',
    hy2_obfs_password: 'obfs-secret',
    hy2_mport: '40000-50000',
    tuic_congestion_control: 'bbr',
    tuic_zero_rtt: true,
    shadowtls_version: 3,
    shadowtls_password: 'shadow-secret',
  };

  it('preserves valid advanced fields and clears fields hidden for the current combination', () => {
    const values = inboundFormValues(existing);
    values.remark = 'edge-updated';
    values.port = 8443;

    const payload = buildFullInboundPayload(existing, values);

    expect(payload).toMatchObject({
      remark: 'edge-updated',
      port: 8443,
      reality_private_key: 'private-key',
      reality_public_key: 'public-key',
      xhttp_path: '/xhttp',
      xhttp_mode: 'stream-one',
      hy2_obfs_password: '',
      hy2_mport: '',
      tuic_zero_rtt: false,
      shadowtls_password: '',
      tls_alpn: '',
    });
    expect(payload).not.toHaveProperty('id');
    expect(payload).not.toHaveProperty('clients');
    expect(payload).not.toHaveProperty('traffic_total');
    expect(payload).not.toHaveProperty('client_traffic');
  });

  it('provides defaults for advanced fields on new inbound', () => {
    const inbound = createDefaultInbound();
    const payload = buildFullInboundPayload(null, inboundFormValues(inbound));

    expect(payload).toMatchObject({
      protocol: 'vless',
      security: 'reality',
      reality_dest: 'www.cloudflare.com:443',
      reality_server_names: 'www.cloudflare.com',
      tls_fingerprint: 'chrome',
      tls_alpn: '',
      ss_method: '',
      xhttp_mode: '',
      hy2_up_mbps: 0,
      hy2_down_mbps: 0,
      tuic_congestion_control: '',
      shadowtls_version: 0,
    });
  });

  it('applies recommended and compatibility templates without leaking unrelated advanced fields', () => {
    const base = inboundFormValues(createDefaultInbound());

    const recommended = applyInboundTemplate(base, 'recommended');
    const recommendedAgain = applyInboundTemplate(base, 'recommended');
    expect(recommended).toMatchObject({
      protocol: 'vless',
      network: 'tcp',
      security: 'reality',
      port: 0,
      reality_dest: 'www.cloudflare.com:443',
      reality_server_names: 'www.cloudflare.com',
      tls_fingerprint: 'chrome',
      tls_alpn: '',
    });
    expect(recommended.reality_short_id).toHaveLength(8);
    expect(recommendedAgain.reality_short_id).toHaveLength(8);
    expect(recommendedAgain.reality_short_id).not.toBe(recommended.reality_short_id);

    const compatible = applyInboundTemplate(recommended, 'compatible');
    expect(compatible).toMatchObject({
      protocol: 'vmess',
      network: 'ws',
      security: 'tls',
      ws_path: '/migate',
      ws_host: 'example.com',
      tls_sni: 'example.com',
    });
    expect(compatible.uuid).toBe(recommended.uuid);
    expect(compatible.reality_dest).toBe('');
    expect(compatible.reality_server_names).toBe('');
    expect(compatible.reality_short_id).toBe('');
  });

  it('applies UDP fast and light templates with generated secrets', () => {
    const base = inboundFormValues(createDefaultInbound());

    const udpFast = applyInboundTemplate(base, 'udp-fast');
    const udpFastAgain = applyInboundTemplate(base, 'udp-fast');
    expect(udpFast).toMatchObject({
      protocol: 'hysteria2',
      network: 'udp',
      security: 'tls',
      port: 0,
      hy2_up_mbps: 100,
      hy2_down_mbps: 100,
      hy2_obfs: 'salamander',
      tls_sni: 'example.com',
      hy2_mport: '',
    });
    expect(udpFast.uuid).toMatch(/^[0-9a-f]{32}$/);
    expect(udpFast.hy2_obfs_password).toHaveLength(18);
    expect(udpFastAgain.hy2_obfs_password).toHaveLength(18);
    expect(udpFastAgain.hy2_obfs_password).not.toBe(udpFast.hy2_obfs_password);

    const light = applyInboundTemplate(base, 'light');
    expect(light).toMatchObject({
      protocol: 'shadowsocks',
      network: 'tcp',
      security: 'none',
      port: 0,
      ss_method: '2022-blake3-aes-128-gcm',
    });
    expect(light.uuid).toMatch(/^[0-9a-f]{24}$/);
    expect(light.hy2_obfs).toBe('');
    expect(light.hy2_obfs_password).toBe('');
    expect(light.hy2_mport).toBe('');
    expect(light.tls_sni).toBe('');
  });

  it('keeps generated inbound internal ID format aligned with regenerate behavior', () => {
    const base = inboundFormValues(createDefaultInbound());
    expect(base.uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);

    expect(applyInboundTemplate(base, 'recommended').uuid).toMatch(/^[0-9a-f-]{36}$/i);
    expect(applyInboundTemplate(base, 'compatible').uuid).toMatch(/^[0-9a-f-]{36}$/i);
    expect(applyInboundTemplate(base, 'password').uuid).toMatch(/^[0-9a-f-]{36}$/i);
    expect(applyInboundTemplate(base, 'light').uuid).toMatch(/^[0-9a-f]{24}$/);
    expect(applyInboundTemplate(base, 'local-socks').uuid).toMatch(/^[0-9a-f]{24}$/);
    expect(applyInboundTemplate(base, 'local-http').uuid).toMatch(/^[0-9a-f]{24}$/);
    expect(applyInboundTemplate(base, 'udp-fast').uuid).toMatch(/^[0-9a-f]{32}$/);
    expect(applyInboundTemplate(base, 'low-latency').uuid).toMatch(/^[0-9a-f]{32}$/);
    expect(applyInboundTemplate(base, 'handshake-mask').uuid).toMatch(/^[0-9a-f]{32}$/);

    expect(sanitizeInboundFormValues(base, { protocol: 'socks' }).uuid).toMatch(/^[0-9a-f]{24}$/);
    expect(sanitizeInboundFormValues(base, { protocol: 'tuic' }).uuid).toMatch(/^[0-9a-f]{32}$/);
    expect(sanitizeInboundFormValues(applyInboundTemplate(base, 'udp-fast'), { protocol: 'vless' }).uuid).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it('sanitizes protocol, transport, and security changes to supported combinations', () => {
    const hy2 = applyInboundTemplate(inboundFormValues(createDefaultInbound()), 'udp-fast');
    const vless = sanitizeInboundFormValues(hy2, { protocol: 'vless' });
    expect(vless).toMatchObject({
      protocol: 'vless',
      network: 'tcp',
      security: 'reality',
      reality_dest: 'www.cloudflare.com:443',
      reality_server_names: 'www.cloudflare.com',
      hy2_obfs: '',
      hy2_obfs_password: '',
    });

    const reality = applyInboundTemplate(inboundFormValues(createDefaultInbound()), 'recommended');
    const vmess = sanitizeInboundFormValues(reality, { protocol: 'vmess' });
    expect(vmess).toMatchObject({
      protocol: 'vmess',
      network: 'ws',
      security: 'tls',
      reality_dest: '',
      reality_server_names: '',
      reality_short_id: '',
      ws_path: '',
      ws_host: '',
      tls_fingerprint: 'chrome',
    });

    const ws = sanitizeInboundFormValues(reality, { network: 'ws' });
    expect(ws).toMatchObject({
      protocol: 'vless',
      network: 'ws',
      security: 'tls',
      reality_dest: '',
      reality_server_names: '',
      reality_short_id: '',
      ws_path: '',
      ws_host: '',
      tls_fingerprint: 'chrome',
    });
  });

  it('keeps socks/http as local proxy inbounds and drops unsupported transports', () => {
    const socks = sanitizeInboundFormValues(inboundFormValues(createDefaultInbound()), { protocol: 'socks' });
    expect(socks).toMatchObject({ protocol: 'socks', network: 'tcp', security: 'none' });
    expect(supportsInboundShareLink('socks')).toBe(true);
    expect(supportsInboundShareLink('http')).toBe(true);
    expect(supportsInboundShareLink('vless')).toBe(true);

    const invalid = sanitizeInboundFormValues(inboundFormValues(createDefaultInbound()), { network: 'quic' });
    expect(invalid.network).toBe('tcp');
  });

  it('uses API inbound capabilities as the active matrix with fallback reset', () => {
    applyInboundCapabilitiesFromAPI([
      {
        protocol: 'mystery',
        core: 'sing-box',
        networks: ['udp'],
        securities: ['tls'],
        default_network: 'udp',
        default_security: 'tls',
        security_by_network: { default: ['tls'] },
        advanced_fields: [],
        credential_type: 'password',
        subscription: 'none',
      },
      {
        protocol: 'tuic',
        core: 'sing-box',
        networks: ['udp'],
        securities: ['tls'],
        default_network: 'udp',
        default_security: 'tls',
        security_by_network: { default: ['tls'] },
        advanced_fields: ['tls_cert_file', 'tls_key_file', 'tls_sni', 'tuic_zero_rtt'],
        credential_type: 'credential_id_password',
        subscription: 'none',
        share_link: false,
        local_proxy_inbound: false,
      },
      {
        protocol: 'vless',
        core: 'xray',
        networks: ['grpc'],
        securities: ['none', 'reality'],
        default_network: 'grpc',
        default_security: 'reality',
        security_by_network: { default: ['none'], grpc: ['none', 'reality'] },
        advanced_fields: ['grpc_service_name', 'reality_dest', 'reality_server_names', 'reality_private_key', 'reality_public_key'],
        credential_type: 'uuid',
        subscription: 'full',
        share_link: true,
      },
    ]);

    expect(inboundProtocolOptions()).toEqual(['tuic', 'vless']);
    expect(allowedInboundNetworks('vless')).toEqual(['grpc']);
    expect(allowedInboundSecurities('vless', 'grpc')).toEqual(['none', 'reality']);
    expect(inboundCredentialType('tuic')).toBe('credential_id_password');
    expect(supportsInboundShareLink('tuic')).toBe(false);

    const normalized = sanitizeInboundFormValues(inboundFormValues(createDefaultInbound()), { protocol: 'vless' });
    expect(normalized).toMatchObject({ protocol: 'vless', network: 'grpc', security: 'reality' });

    resetInboundCapabilitiesForTest();
    expect(inboundProtocolOptions()).toContain('shadowtls');
    expect(supportsInboundShareLink('tuic')).toBe(true);
  });

  it('uses share_link as the authoritative frontend share capability', () => {
    applyInboundCapabilitiesFromAPI([
      {
        protocol: 'vless',
        core: 'xray',
        networks: ['tcp'],
        securities: ['none'],
        default_network: 'tcp',
        default_security: 'none',
        security_by_network: { default: ['none'] },
        advanced_fields: [],
        credential_type: 'uuid',
        subscription: 'full',
        share_link: false,
      },
      {
        protocol: 'shadowtls',
        core: 'sing-box',
        networks: ['tcp'],
        securities: ['none'],
        default_network: 'tcp',
        default_security: 'none',
        security_by_network: { default: ['none'] },
        advanced_fields: ['tls_sni', 'shadowtls_version'],
        credential_type: 'password',
        subscription: 'none',
        share_link: true,
      },
    ]);

    expect(supportsInboundShareLink('vless')).toBe(false);
    expect(supportsInboundShareLink('shadowtls')).toBe(true);
  });

  it('falls back safely when API capability fields are incomplete', () => {
    expect(() => applyInboundCapabilitiesFromAPI([
      {
        protocol: 'vless',
        core: 'xray',
        networks: undefined,
        securities: undefined,
        default_network: '',
        default_security: '',
        security_by_network: undefined,
        advanced_fields: undefined,
        credential_type: '',
        subscription: '',
      } as unknown as InboundCapability,
    ])).not.toThrow();

    expect(inboundProtocolOptions()).toEqual(['vless']);
    expect(allowedInboundNetworks('vless')).toContain('tcp');
    expect(allowedInboundSecurities('vless', 'tcp')).toContain('reality');
    expect(supportsInboundShareLink('vless')).toBe(true);
  });

  it('keeps ShadowTLS tls_sni as a protocol handshake field from API capabilities', () => {
    applyInboundCapabilitiesFromAPI([
      {
        protocol: 'shadowtls',
        core: 'sing-box',
        networks: ['tcp'],
        securities: ['none'],
        default_network: 'tcp',
        default_security: 'none',
        security_by_network: { default: ['none'] },
        advanced_fields: ['tls_sni', 'shadowtls_version'],
        credential_type: 'password',
        subscription: 'none',
      },
    ]);

    expect(enabledInboundAdvancedFields({ protocol: 'shadowtls', network: 'tcp', security: 'none' }).has('tls_sni')).toBe(true);
  });

  it('removes invalid advanced fields from the submitted payload after manual switches', () => {
    const values = inboundFormValues(existing);
    values.protocol = 'vmess';
    values.network = 'ws';
    values.security = 'reality';

    const payload = buildFullInboundPayload(existing, values);

    expect(payload).toMatchObject({
      protocol: 'vmess',
      network: 'ws',
      security: 'tls',
      ws_path: '/ws',
      ws_host: 'cdn.example.com',
      reality_dest: '',
      reality_server_names: '',
      reality_short_id: '',
      reality_private_key: '',
      reality_public_key: '',
      hy2_mport: '',
      shadowtls_password: '',
      tls_alpn: 'h2,http/1.1',
    });
  });

  it('keeps ShadowTLS handshake SNI but clears its unsupported inbound password', () => {
    const values = inboundFormValues({
      ...existing,
      protocol: 'shadowtls',
      network: 'tcp',
      security: 'none',
      tls_sni: 'handshake.example.com',
      shadowtls_version: 3,
      shadowtls_password: 'legacy-shadow-password',
    });

    const payload = buildFullInboundPayload(existing, values);

    expect(payload).toMatchObject({
      protocol: 'shadowtls',
      network: 'tcp',
      security: 'none',
      tls_sni: 'handshake.example.com',
      shadowtls_version: 3,
      shadowtls_password: '',
    });
  });

  it('shows saved-client link actions for user-password proxy protocols', () => {
    expect(supportsInboundShareLink('socks')).toBe(true);
    expect(supportsInboundShareLink('http')).toBe(true);
    expect(supportsInboundShareLink('shadowtls')).toBe(false);
    expect(supportsInboundShareLink('vless')).toBe(true);
    expect(savedClientLinkActions('socks')).toEqual(['share']);
    expect(savedClientLinkActions('http')).toEqual(['share']);
    expect(savedClientLinkActions('shadowtls')).toEqual([]);
    expect(savedClientLinkActions('vless')).toEqual(['share']);
  });

  it('normalizes missing numeric advanced fields when editing a basic inbound', () => {
    const basic: Inbound = {
      id: 13,
      remark: 'plain',
      protocol: 'vless',
      port: 8443,
      network: 'tcp',
      security: 'none',
      enabled: true,
      uuid: '22222222-2222-4222-8222-222222222222',
      clients: [],
    };

    const payload = buildFullInboundPayload(basic, inboundFormValues(basic));

    expect(payload.hy2_up_mbps).toBe(0);
    expect(payload.hy2_down_mbps).toBe(0);
    expect(payload.shadowtls_version).toBe(0);
    expect(typeof payload.hy2_up_mbps).toBe('number');
    expect(typeof payload.hy2_down_mbps).toBe('number');
    expect(typeof payload.shadowtls_version).toBe('number');
  });

  it('keeps an empty inbound port as zero so the backend can auto-assign it', () => {
    const values = inboundFormValues(createDefaultInbound());
    values.port = 0;

    const payload = buildFullInboundPayload(null, values);

    expect(payload.port).toBe(0);
  });

  it('attaches an initial client only for new node payloads', () => {
    const values = inboundFormValues(createDefaultInbound());
    const client = buildClientPayload(clientFormValues(createDefaultInbound()), values.protocol);
    const created = buildFullInboundPayload(null, values, client);
    const updated = buildFullInboundPayload(existing, values, client);

    expect(created.initial_client).toMatchObject({ email: '首个客户端', enabled: true });
    expect(updated).not.toHaveProperty('initial_client');
  });

  it('keeps VMess template as WS + TLS by default', () => {
    const values = applyInboundTemplate(inboundFormValues(createDefaultInbound()), 'compatible');

    expect(values).toMatchObject({
      protocol: 'vmess',
      network: 'ws',
      security: 'tls',
      ws_path: '/migate',
      tls_sni: 'example.com',
    });
  });

  it('creates a non-empty default client name for new node payloads', () => {
    const inbound = createDefaultInbound();
    const values = clientFormValues(inbound);

    expect(values.email).toBe('首个客户端');
    expect(buildClientPayload(values, inbound.protocol).email).toBe('首个客户端');
  });

  it('normalizes blank inbound ports to zero for backend auto-assignment', () => {
    const values = inboundFormValues(createDefaultInbound());
    values.port = '' as unknown as typeof values.port;

    const payload = buildFullInboundPayload(null, values);

    expect(payload.port).toBe(0);
  });

  it('allows attaching a settings certificate only after it is issued with both files', () => {
    expect(hasAttachableSettingCert({ domain: 'example.com', email: 'admin@example.com', issued: false, cert_path: '/etc/migate/certs/example/fullchain.pem', key_path: '/etc/migate/certs/example/privkey.pem' })).toBe(false);
    expect(hasAttachableSettingCert({ domain: 'example.com', email: 'admin@example.com', issued: true, cert_path: '/etc/migate/certs/example/fullchain.pem', key_path: '' })).toBe(false);
    expect(hasAttachableSettingCert({ domain: 'example.com', email: 'admin@example.com', issued: true, cert_path: '   ', key_path: '/etc/migate/certs/example/privkey.pem' })).toBe(false);
    expect(hasAttachableSettingCert({ domain: 'example.com', email: 'admin@example.com', issued: true, cert_path: '/etc/migate/certs/example/fullchain.pem', key_path: '/etc/migate/certs/example/privkey.pem' })).toBe(true);
  });

  it('merges lightweight traffic refresh without replacing full config fields', () => {
    const current: Inbound[] = [{
      id: 1,
      remark: 'edge',
      protocol: 'vless',
      port: 443,
      network: 'tcp',
      security: 'reality',
      enabled: true,
      uuid: '11111111-1111-4111-8111-111111111111',
      reality_private_key: 'private-key',
      clients: [{ id: 10, inbound_id: 1, email: 'sam@example.com', uuid: 'client-uuid', enabled: true, traffic_limit: 1000, expiry_at: 0 }],
    }];
    const traffic: Inbound[] = [{
      id: 1,
      remark: 'edge',
      protocol: 'vless',
      port: 443,
      network: 'tcp',
      security: 'reality',
      enabled: false,
      clients: [{ id: 10, inbound_id: 1, email: 'sam@example.com', uuid: 'client-uuid', enabled: false, up: 12, down: 34, traffic_limit: 2000, expiry_at: 99 }],
      traffic_up: 12,
      traffic_down: 34,
      traffic_total: 46,
      rate_up: 1,
      rate_down: 2,
      traffic_status: 'ok',
      client_traffic: { '10': { up: 12, down: 34, rate_up: 1, rate_down: 2, status: 'ok' } },
    }];

    const [merged] = mergeInboundTraffic(current, traffic);

    expect(merged.enabled).toBe(false);
    expect(merged.reality_private_key).toBe('private-key');
    expect(merged.traffic_total).toBe(46);
    expect(merged).toMatchObject({ rate_up: 1, rate_down: 2, traffic_status: 'ok' });
    expect(merged.clients?.[0]).toMatchObject({ email: 'sam@example.com', enabled: false, up: 12, down: 34, rate_up: 1, rate_down: 2, traffic_status: 'ok', traffic_limit: 2000, expiry_at: 99 });
  });
});

describe('client form helpers', () => {
  it('converts traffic limits between GB and bytes', () => {
    expect(gbToBytes(1)).toBe(1073741824);
    expect(gbToBytes(1.5)).toBe(1610612736);
    expect(gbToBytes(0)).toBe(0);
    expect(bytesToGB(1073741824)).toBe(1);
    expect(bytesToGB(1610612736)).toBe(1.5);
  });

  it('reflects existing client traffic and custom expiry values', () => {
    const inbound = createDefaultInbound();
    const expiryAt = Math.floor(new Date('2030-01-01T23:59:59').getTime() / 1000);
    const values = clientFormValues(inbound, {
      id: 1,
      inbound_id: inbound.id,
      email: 'sam',
      uuid: '11111111-1111-4111-8111-111111111111',
      enabled: true,
      traffic_limit: 5 * 1024 ** 3,
      expiry_at: expiryAt,
    });

    expect(values.traffic_limit_gb).toBe(5);
    expect(values.expiry_mode).toBe('custom');
    expect(values.expiry_date).toBe('2030-01-01');
  });

  it('builds the API payload with bytes and the current expiry contract', () => {
    const payload = buildClientPayload({
      email: 'sam',
      uuid: 'secret',
      enabled: true,
      traffic_limit_gb: 2,
      expiry_mode: 'custom',
      expiry_date: '2030-01-01',
    });

    const expectedExpiry = Math.floor(new Date('2030-01-01T23:59:59').getTime() / 1000);

    expect(payload).toMatchObject({
      email: 'sam',
      uuid: 'secret',
      enabled: true,
      traffic_limit: 2 * 1024 ** 3,
      expiry_at: expectedExpiry,
    });
  });

  it('builds protocol-specific client credential payloads', () => {
    const tuicValues = clientFormValues({ ...createDefaultInbound(), protocol: 'tuic', network: 'udp', security: 'tls' });
    tuicValues.credential_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    tuicValues.password = 'tuic-secret';
    expect(buildClientPayload(tuicValues, 'tuic')).toMatchObject({
      uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      credential_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      password: 'tuic-secret',
    });

    const socksValues = clientFormValues({ ...createDefaultInbound(), protocol: 'socks', network: 'tcp', security: 'none' });
    socksValues.credential_id = 'sam';
    socksValues.password = 'secret';
    expect(buildClientPayload(socksValues, 'socks')).toMatchObject({ uuid: 'sam', credential_id: 'sam', password: 'secret' });

    const trojanValues = clientFormValues({ ...createDefaultInbound(), protocol: 'trojan', network: 'tcp', security: 'tls' });
    trojanValues.uuid = 'old-internal-id';
    trojanValues.credential_id = '';
    trojanValues.password = 'trojan-secret';
    expect(buildClientPayload(trojanValues, 'trojan')).toMatchObject({ uuid: 'trojan-secret', credential_id: '', password: 'trojan-secret' });

    const editingTrojan = clientFormValues({ ...createDefaultInbound(), protocol: 'trojan', network: 'tcp', security: 'tls' }, {
      id: 7,
      inbound_id: 1,
      email: 'trojan-user',
      uuid: 'stored-password',
      enabled: true,
    });
    expect(editingTrojan.password).toBe('stored-password');
    expect(editingTrojan.credential_id).toBe('');
    expect(buildClientPayload(editingTrojan, 'trojan')).toMatchObject({ uuid: 'stored-password', credential_id: '', password: 'stored-password' });
  });
});
