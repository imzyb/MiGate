import { describe, expect, it } from 'vitest';
import type { Inbound, Outbound } from '../api/types';
import { buildInboundTagLookup, buildTopologyGraph } from './topologyGraph';

const inbounds: Inbound[] = [
  {
    id: 7,
    remark: 'edge-hk',
    protocol: 'VLESS',
    port: 443,
    network: 'tcp',
    security: 'reality',
    enabled: true,
    clients: [
      { id: 11, inbound_id: 7, email: 'alice@example.com', uuid: 'u-1', enabled: true, up: 1024, down: 2048, traffic_limit: 4096 },
      { id: 12, inbound_id: 7, email: 'bob@example.com', uuid: 'u-2', enabled: false },
    ],
  },
  {
    id: 8,
    remark: '',
    protocol: 'vmess',
    port: 8443,
    network: 'ws',
    security: 'tls',
    enabled: false,
    clients: [],
  },
];

const outbounds: Outbound[] = [
  { id: 1, tag: 'direct', protocol: 'freedom', enabled: true },
  { id: 2, tag: 'proxy-a', remark: 'Tokyo relay', protocol: 'socks', address: '127.0.0.1', port: 1080, enabled: false },
];

describe('topology graph helpers', () => {
  it('generates inbound, client and outbound nodes with display data', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, []);

    expect(graph.nodes.find((node) => node.id === 'inbound:7')?.data).toMatchObject({
      kind: 'inbound',
      title: 'edge-hk',
      subtitle: 'inbound-7-vless',
      enabled: true,
    });
    expect(graph.nodes.find((node) => node.id === 'client:11')?.data).toMatchObject({
      kind: 'client',
      title: 'alice@example.com',
      enabled: true,
    });
    expect(graph.nodes.find((node) => node.id === 'outbound:proxy-a')?.data).toMatchObject({
      kind: 'outbound',
      title: 'proxy-a',
      subtitle: 'Tokyo relay',
      enabled: false,
    });
    expect(graph.edges.find((edge) => edge.id === 'client-7-11')?.data).toMatchObject({
      kind: 'client-inherits',
      label: '附属客户端',
      enabled: true,
    });
  });

  it('matches inbound_tag by generated tag and remark alias', () => {
    const lookup = buildInboundTagLookup(inbounds);
    expect(lookup.get('inbound-7-vless')?.id).toBe(7);
    expect(lookup.get('edge-hk')?.id).toBe(7);

    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 21, inbound_tag: 'inbound-7-vless', outbound_id: 1, outbound_tag: 'direct', enabled: true },
      { id: 22, inbound_tag: 'edge-hk', outbound_id: 2, outbound_tag: 'proxy-a', enabled: true },
    ]);

    expect(graph.edges.find((edge) => edge.id.startsWith('rule-21-7'))).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:direct',
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-22-7'))).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:proxy-a',
    });
  });

  it('expands empty inbound_tag rules to all inbounds', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 31, inbound_tag: '', outbound_id: 1, outbound_tag: 'direct', enabled: true },
      { id: 32, inbound_tag: '   ', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    const routingEdges = graph.edges.filter((edge) => edge.id.startsWith('rule-31-'));
    expect(routingEdges).toHaveLength(2);
    expect(routingEdges.map((edge) => edge.source).sort()).toEqual(['inbound:7', 'inbound:8']);
    expect(routingEdges.every((edge) => edge.data?.kind === 'all-inbounds-routing')).toBe(true);

    const blankTagEdges = graph.edges.filter((edge) => edge.id.startsWith('rule-32-'));
    expect(blankTagEdges).toHaveLength(2);
    expect(blankTagEdges.every((edge) => edge.data?.kind === 'all-inbounds-routing')).toBe(true);
    expect(blankTagEdges.every((edge) => edge.label === '#32 全部入站')).toBe(true);
  });

  it('creates a missing outbound node when outbound_id is not found', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 41, inbound_tag: 'inbound-7-vless', outbound_id: 99, outbound_tag: 'deleted-proxy', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'outbound:id:99')?.data).toMatchObject({
      kind: 'missing-outbound',
      subtitle: '路由引用的出站不存在 · deleted-proxy',
      missing: true,
      enabled: false,
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-41-7'))?.data).toMatchObject({
      kind: 'routing',
      missingTarget: true,
    });
  });

  it('creates a missing inbound node when inbound_tag is not found', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 42, inbound_tag: 'deleted-inbound', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'inbound-missing:deleted-inbound')?.data).toMatchObject({
      kind: 'missing-inbound',
      title: 'deleted-inbound',
      missing: true,
      enabled: false,
    });
    expect(graph.nodes.find((node) => node.id === 'inbound-missing:deleted-inbound')?.position.y).toBeGreaterThan(
      graph.nodes.find((node) => node.id === 'client:12')?.position.y || 0,
    );
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-42-missing-deleted-inbound'))).toMatchObject({
      source: 'inbound-missing:deleted-inbound',
      target: 'outbound:direct',
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-42-missing-deleted-inbound'))?.data).toMatchObject({
      kind: 'routing',
      enabled: false,
    });
  });

  it('resolves inbound source by inbound_id before stale inbound_tag', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 43, inbound_id: 8, inbound_tag: 'edge-hk', outbound_id: 1, outbound_tag: 'direct', enabled: true },
      { id: 44, inbound_id: 7, inbound_tag: '', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.edges.find((edge) => edge.id.startsWith('rule-43-8'))).toMatchObject({
      source: 'inbound:8',
      target: 'outbound:direct',
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-44-7'))).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:direct',
    });
    expect(graph.nodes.find((node) => node.id === 'inbound-missing:edge-hk')).toBeUndefined();
  });

  it('creates a missing inbound node when inbound_id is not found', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 45, inbound_id: 99, inbound_tag: 'deleted-inbound', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'inbound-missing:id:99')?.data).toMatchObject({
      kind: 'missing-inbound',
      title: 'id:99',
      subtitle: '路由引用的入站不存在 · deleted-inbound',
      missing: true,
      enabled: false,
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-45-missing-id-99'))).toMatchObject({
      source: 'inbound-missing:id:99',
      target: 'outbound:direct',
    });
  });

  it('marks disabled rules and nodes in graph data', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 51, inbound_tag: 'inbound-7-vless', outbound_id: 1, outbound_tag: 'direct', enabled: false },
      { id: 52, inbound_tag: 'inbound-8-vmess', outbound_id: 2, outbound_tag: 'proxy-a', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'inbound:8')?.data.enabled).toBe(false);
    expect(graph.nodes.find((node) => node.id === 'client:12')?.data.enabled).toBe(false);
    expect(graph.nodes.find((node) => node.id === 'outbound:proxy-a')?.data.enabled).toBe(false);
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-51-7'))?.data?.enabled).toBe(false);
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-52-8'))?.data?.enabled).toBe(false);

    const disabledOutboundGraph = buildTopologyGraph(inbounds, outbounds, [
      { id: 53, inbound_tag: 'inbound-7-vless', outbound_id: 2, outbound_tag: 'proxy-a', enabled: true },
    ]);
    expect(disabledOutboundGraph.edges.find((edge) => edge.id.startsWith('rule-53-7'))?.data?.enabled).toBe(false);
  });

  it('does not create fake client-to-outbound routing edges', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 61, inbound_tag: 'inbound-7-vless', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.edges.some((edge) => edge.source.startsWith('client:') && edge.target.startsWith('outbound:'))).toBe(false);
  });

  it('hides management direct system protection from the topology canvas', () => {
    const graph = buildTopologyGraph(inbounds, [
      ...outbounds,
      { id: 99, tag: 'migate-system-direct', protocol: 'freedom', enabled: true },
    ], [
      { id: 610, inbound_tag: '', outbound_id: 99, outbound_tag: 'migate-system-direct', ip: '103.193.149.217', enabled: true },
      { id: 611, inbound_tag: 'inbound-7-vless', outbound_id: 2, outbound_tag: 'proxy-a', enabled: true },
    ]);

    expect(graph.nodes.some((node) => node.id.includes('migate-system-direct'))).toBe(false);
    expect(graph.edges.some((edge) => edge.data?.ruleId === 610 || edge.target.includes('migate-system-direct'))).toBe(false);
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-611-7'))).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:proxy-a',
    });
  });

  it('creates real client-to-outbound routing edges for client rules', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 62, inbound_tag: 'inbound-7-vless', client_id: 11, client_email: 'alice@example.com', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.edges.find((edge) => edge.id.startsWith('rule-62-client-11'))).toMatchObject({
      source: 'client:11',
      target: 'outbound:direct',
      data: {
        kind: 'client-routing',
        ruleId: 62,
      },
    });
    expect(graph.edges.some((edge) => edge.id.startsWith('rule-62-7') && edge.source === 'inbound:7' && edge.target === 'outbound:direct')).toBe(false);
    expect(graph.edges.find((edge) => edge.id === 'default-direct-client-11')).toBeUndefined();
  });

  it('keeps client default direct inheritance when client routing target is unavailable', () => {
    const disabledTargetGraph = buildTopologyGraph(inbounds, outbounds, [
      { id: 64, inbound_tag: 'inbound-7-vless', client_id: 11, client_email: 'alice@example.com', outbound_id: 2, outbound_tag: 'proxy-a', enabled: true },
    ]);
    expect(disabledTargetGraph.edges.find((edge) => edge.id.startsWith('rule-64-client-11'))?.data?.enabled).toBe(false);
    expect(disabledTargetGraph.edges.find((edge) => edge.id === 'default-direct-client-11')).toMatchObject({
      source: 'client:11',
      target: 'outbound:direct',
    });

    const missingTargetGraph = buildTopologyGraph(inbounds, outbounds, [
      { id: 65, inbound_tag: 'inbound-7-vless', client_id: 11, client_email: 'alice@example.com', outbound_id: 99, outbound_tag: 'deleted-proxy', enabled: true },
    ]);
    expect(missingTargetGraph.edges.find((edge) => edge.id.startsWith('rule-65-client-11'))?.data?.enabled).toBe(false);
    expect(missingTargetGraph.edges.find((edge) => edge.id === 'default-direct-client-11')).toMatchObject({
      source: 'client:11',
      target: 'outbound:direct',
    });
  });

  it('creates a missing client node for deleted client routing rules', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 63, inbound_tag: 'inbound-7-vless', client_id: 99, client_email: 'deleted@example.com', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'client-missing:63')?.data).toMatchObject({
      kind: 'missing-client',
      title: 'deleted@example.com',
      missing: true,
      enabled: false,
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-63-missing-client-99'))).toMatchObject({
      source: 'client-missing:63',
      target: 'outbound:direct',
      data: {
        kind: 'client-routing',
        enabled: false,
      },
    });
  });

  it('uses unique missing client nodes for multiple rules referencing the same deleted client', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 66, inbound_tag: 'inbound-7-vless', client_id: 99, client_email: 'deleted@example.com', outbound_id: 1, outbound_tag: 'direct', enabled: true },
      { id: 67, inbound_tag: 'deleted-inbound', client_id: 99, client_email: 'deleted@example.com', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.nodes.filter((node) => node.id.startsWith('client-missing:')).map((node) => node.id).sort()).toEqual(['client-missing:66', 'client-missing:67']);
    expect(graph.nodes.find((node) => node.id === 'inbound-missing:deleted-inbound')?.data).toMatchObject({
      kind: 'missing-inbound',
      missing: true,
    });
  });

  it('adds a default direct visual edge only for inbounds without enabled routes', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 71, inbound_tag: 'inbound-7-vless', outbound_id: 1, outbound_tag: 'direct', enabled: true },
      { id: 72, inbound_tag: 'inbound-8-vmess', outbound_id: 2, outbound_tag: 'proxy-a', enabled: false },
    ]);

    expect(graph.edges.find((edge) => edge.id === 'default-direct-7')).toBeUndefined();
    expect(graph.edges.find((edge) => edge.id === 'default-direct-8')).toMatchObject({
      source: 'inbound:8',
      target: 'outbound:direct',
      data: {
        kind: 'default-direct',
        label: '默认出站',
        enabled: false,
      },
    });
    expect(graph.edges.find((edge) => edge.id === 'default-direct-client-11')).toBeUndefined();
  });

  it('keeps default direct visual edges when enabled routes point to unavailable outbounds', () => {
    const disabledTargetGraph = buildTopologyGraph(inbounds, outbounds, [
      { id: 73, inbound_tag: 'inbound-7-vless', outbound_id: 2, outbound_tag: 'proxy-a', enabled: true },
    ]);
    expect(disabledTargetGraph.edges.find((edge) => edge.id.startsWith('rule-73-7'))?.data?.enabled).toBe(false);
    expect(disabledTargetGraph.edges.find((edge) => edge.id === 'default-direct-7')).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:direct',
      data: { kind: 'default-direct', enabled: true },
    });

    const missingTargetGraph = buildTopologyGraph(inbounds, outbounds, [
      { id: 74, inbound_tag: 'inbound-7-vless', outbound_id: 99, outbound_tag: 'missing-proxy', enabled: true },
    ]);
    expect(missingTargetGraph.edges.find((edge) => edge.id.startsWith('rule-74-7'))?.data?.enabled).toBe(false);
    expect(missingTargetGraph.edges.find((edge) => edge.id === 'default-direct-7')).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:direct',
      data: { kind: 'default-direct', enabled: true },
    });
  });

  it('does not create default direct edges when direct outbound is missing', () => {
    const graph = buildTopologyGraph(inbounds, outbounds.filter((outbound) => outbound.tag !== 'direct'), []);

    expect(graph.edges.some((edge) => edge.data?.kind === 'default-direct')).toBe(false);
  });

  it('marks routing edges invalid when outbound profile does not support the source core', () => {
    const mixedInbounds: Inbound[] = [
      { id: 1, remark: 'xray-edge', protocol: 'vless', core: 'xray', port: 443, network: 'tcp', security: 'none', enabled: true, clients: [] },
      { id: 2, remark: 'sb-edge', protocol: 'hysteria2', core: 'sing-box', port: 8443, network: 'udp', security: 'tls', enabled: true, clients: [] },
    ];
    const mixedOutbounds: Outbound[] = [
      { id: 1, tag: 'direct', protocol: 'freedom', enabled: true },
      { id: 2, tag: 'hy2-out', protocol: 'hysteria2', supported_cores: ['sing-box'], enabled: true },
      { id: 3, tag: 'shared-socks', protocol: 'socks', supported_cores: ['xray', 'sing-box'], enabled: true },
    ];
    const graph = buildTopologyGraph(mixedInbounds, mixedOutbounds, [
      { id: 81, inbound_tag: 'inbound-1-vless', outbound_id: 2, outbound_tag: 'hy2-out', enabled: true },
      { id: 82, inbound_tag: 'inbound-2-hysteria2', outbound_id: 3, outbound_tag: 'shared-socks', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'inbound:1')?.data.meta).toContainEqual({ label: '内核', value: 'xray' });
    expect(graph.nodes.find((node) => node.id === 'outbound:hy2-out')?.data.meta).toContainEqual({ label: '内核', value: 'sing-box' });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-81-1'))?.data).toMatchObject({
      enabled: false,
      invalidTarget: true,
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-82-2'))?.data).toMatchObject({
      enabled: true,
      invalidTarget: false,
    });
  });

  it('shows tag-only routing rules as missing targets', () => {
    const graph = buildTopologyGraph(inbounds, outbounds, [
      { id: 90, inbound_tag: 'inbound-7-vless', outbound_tag: 'direct', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'outbound:missing-outbound-id')?.data).toMatchObject({
      kind: 'missing-outbound',
      missing: true,
      subtitle: '路由引用的出站不存在 · 缺少 outbound_id',
    });
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-90-7'))).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:missing-outbound-id',
      data: {
        missingTarget: true,
      },
    });
  });

  it('resolves routing target by outbound profile id even when tag conflicts', () => {
    const graph = buildTopologyGraph(inbounds, [
      { id: 1, tag: 'direct', protocol: 'freedom', enabled: true },
      { id: 42, tag: 'renamed-proxy', protocol: 'socks', supported_cores: ['xray', 'sing-box'], enabled: true },
    ], [
      { id: 91, inbound_tag: 'inbound-7-vless', outbound_id: 42, outbound_tag: 'old-proxy-tag', enabled: true },
    ]);

    expect(graph.nodes.find((node) => node.id === 'outbound:old-proxy-tag')).toBeUndefined();
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-91-7'))).toMatchObject({
      source: 'inbound:7',
      target: 'outbound:renamed-proxy',
      data: {
        missingTarget: false,
        invalidTarget: false,
      },
    });
  });

  it('builds large multi-inbound client routing graphs without changing edge semantics', () => {
    const largeInbounds: Inbound[] = Array.from({ length: 40 }, (_, inboundIndex) => ({
      id: inboundIndex + 1,
      remark: `edge-${inboundIndex + 1}`,
      protocol: inboundIndex % 2 === 0 ? 'vless' : 'hysteria2',
      core: inboundIndex % 2 === 0 ? 'xray' : 'sing-box',
      port: 20000 + inboundIndex,
      network: inboundIndex % 2 === 0 ? 'tcp' : 'udp',
      security: 'none',
      enabled: true,
      clients: Array.from({ length: 12 }, (_, clientIndex) => ({
        id: (inboundIndex + 1) * 1000 + clientIndex + 1,
        inbound_id: inboundIndex + 1,
        email: `user-${inboundIndex + 1}-${clientIndex + 1}@example.com`,
        uuid: `uuid-${inboundIndex + 1}-${clientIndex + 1}`,
        enabled: true,
      })),
    }));
    const largeOutbounds: Outbound[] = [
      { id: 1, tag: 'direct', protocol: 'freedom', enabled: true },
      { id: 2, tag: 'shared', protocol: 'socks', supported_cores: ['xray', 'sing-box'], enabled: true },
      { id: 3, tag: 'singbox-only', protocol: 'hysteria2', supported_cores: ['sing-box'], enabled: true },
    ];
    const rules = [
      ...largeInbounds.slice(0, 20).map((inbound) => ({ id: 1000 + inbound.id, inbound_tag: `edge-${inbound.id}`, outbound_id: 2, outbound_tag: 'shared', enabled: true })),
      ...largeInbounds.slice(20).map((inbound) => ({ id: 2000 + inbound.id, inbound_tag: `inbound-${inbound.id}-${inbound.protocol.toLowerCase()}`, outbound_id: 1, outbound_tag: 'direct', enabled: true })),
      ...largeInbounds.map((inbound) => ({
        id: 3000 + inbound.id,
        inbound_tag: `edge-${inbound.id}`,
        client_id: inbound.clients?.[5]?.id,
        client_email: inbound.clients?.[5]?.email,
        outbound_id: 2, outbound_tag: 'shared',
        enabled: true,
      })),
      { id: 9991, inbound_tag: '', outbound_id: 1, outbound_tag: 'direct', enabled: false },
      { id: 9992, inbound_tag: 'deleted-inbound', outbound_id: 999, outbound_tag: 'missing-outbound', enabled: true },
      { id: 9993, inbound_tag: 'edge-1', client_id: 999999, client_email: 'deleted@example.com', outbound_id: 1, outbound_tag: 'direct', enabled: true },
    ];

    const graph = buildTopologyGraph(largeInbounds, largeOutbounds, rules);

    expect(graph.nodes.filter((node) => node.data.kind === 'inbound')).toHaveLength(40);
    expect(graph.nodes.filter((node) => node.data.kind === 'client')).toHaveLength(480);
    expect(graph.edges.filter((edge) => edge.data?.kind === 'client-routing')).toHaveLength(41);
    expect(graph.edges.filter((edge) => edge.data?.kind === 'all-inbounds-routing')).toHaveLength(40);
    expect(graph.nodes.find((node) => node.id === 'inbound-missing:deleted-inbound')?.data.missing).toBe(true);
    expect(graph.nodes.find((node) => node.id === 'outbound:id:999')?.data.missing).toBe(true);
    expect(graph.edges.find((edge) => edge.id.startsWith('rule-3001-client-1006'))).toMatchObject({
      source: 'client:1006',
      target: 'outbound:shared',
      data: { kind: 'client-routing', enabled: true },
    });
  });
});
