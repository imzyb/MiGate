import type { Edge, Node } from '@xyflow/react';
import type { Client, Inbound, Outbound, RoutingRule } from '../api/types';
import { coreLabel, inboundCore, outboundSupportedCores, outboundSupportsCore } from '../lib/cores';
import { formatBytes } from '../lib/format';
import { generatedInboundTag } from '../lib/routing';

export type TopologyNodeKind = 'inbound' | 'client' | 'outbound' | 'missing-inbound' | 'missing-client' | 'missing-outbound';
export type TopologyEdgeKind = 'routing' | 'all-inbounds-routing' | 'client-routing' | 'client-inherits' | 'default-direct';

export type TopologyNodeData = {
  kind: TopologyNodeKind;
  title: string;
  subtitle?: string;
  enabled: boolean;
  missing?: boolean;
  invalid?: boolean;
  meta: Array<{ label: string; value: string }>;
};

export type TopologyEdgeData = {
  kind: TopologyEdgeKind;
  label: string;
  enabled: boolean;
  ruleId?: number;
  missingTarget?: boolean;
  invalidTarget?: boolean;
};

export type TopologyGraph = {
  nodes: Array<Node<TopologyNodeData>>;
  edges: Array<Edge<TopologyEdgeData>>;
};

type RoutingSource = {
  nodeId: string;
  edgeKey: string;
  enabled: boolean;
  inboundId?: number;
  clientId?: number;
  missingClient?: boolean;
};

type TopologyLookup = {
  inboundById: Map<number, Inbound>;
  inboundByTag: Map<string, Inbound>;
  outboundById: Map<number, Outbound>;
  clientsByInboundId: Map<number, Map<number, Client>>;
  clientInboundById: Map<number, Inbound>;
};

const inboundX = 0;
const clientX = 360;
const outboundX = 760;
const rowGap = 154;
const clientGap = 96;
const outboundGap = 132;
const systemDirectOutboundTag = 'migate-system-direct';

export function buildTopologyGraph(inbounds: Inbound[], outbounds: Outbound[], routingRules: RoutingRule[]): TopologyGraph {
  const systemDirectOutboundIds = new Set(outbounds.filter((outbound) => isSystemDirectOutbound(outbound)).map((outbound) => outbound.id));
  const visibleOutbounds = outbounds.filter((outbound) => !isSystemDirectOutbound(outbound));
  const visibleRoutingRules = routingRules.filter((rule) => !isSystemDirectRoutingRule(rule, systemDirectOutboundIds));
  const nodes: Array<Node<TopologyNodeData>> = [];
  const edges: Array<Edge<TopologyEdgeData>> = [];
  const lookup = buildTopologyLookup(inbounds, visibleOutbounds);
  const missingInboundTargets = new Map<string, { title: string; subtitle?: string }>();
  const missingClientRules: Array<{ rule: RoutingRule; source: RoutingSource }> = [];
  const missingOutboundTargets = new Map<string, { subtitle?: string }>();
  const routedInboundIds = new Set<number>();
  const explicitlyRoutedClientIds = new Set<number>();

  let y = 0;
  inbounds.forEach((inbound) => {
    const clients = inbound.clients || [];
    const groupHeight = Math.max(rowGap, clients.length * clientGap);
    const centerY = y + groupHeight / 2;
    nodes.push(buildInboundNode(inbound, centerY));

    clients.forEach((client, index) => {
      const clientY = y + 18 + index * clientGap;
      nodes.push(buildClientNode(client, inbound, clientY));
      edges.push(buildClientEdge(inbound, client));
    });

    y += groupHeight + 34;
  });

  const missingInboundStartY = y;
  visibleOutbounds.forEach((outbound, index) => {
    nodes.push(buildOutboundNode(outbound, index * outboundGap));
  });

  const outboundCount = visibleOutbounds.length;
  visibleRoutingRules.forEach((rule) => {
    const outbound = resolveRuleOutbound(rule, lookup.outboundById);
    const missingTarget = !outbound;
    const targetTag = outbound?.tag || missingOutboundTargetKey(rule);
    const targetId = outboundNodeId(targetTag);
    const invalidTarget = !missingTarget && sourcesForCoreCheck(rule, inbounds, lookup).some((source) => {
      const inbound = source.inboundId == null ? undefined : lookup.inboundById.get(source.inboundId);
      return inbound ? !outboundSupportsCore(outbound, inboundCore(inbound)) : false;
    });
    if (missingTarget) {
      missingOutboundTargets.set(targetTag, {
        subtitle: rule.outbound_id ? String(rule.outbound_tag || '').trim() || undefined : '缺少 outbound_id',
      });
    }
    const inboundTag = normalizedInboundTag(rule);
    const inboundID = Number(rule.inbound_id || 0);
    if (inboundID > 0 && !lookup.inboundById.has(inboundID)) {
      missingInboundTargets.set(`id:${inboundID}`, {
        title: `id:${inboundID}`,
        subtitle: String(rule.inbound_tag || '').trim() || undefined,
      });
    } else if (inboundID <= 0 && inboundTag && !lookup.inboundByTag.has(inboundTag)) {
      missingInboundTargets.set(inboundTag, { title: inboundTag });
    }

    const sources = routingSourcesForRule(rule, inbounds, lookup);
    sources.forEach((source, index) => {
      const outboundEnabled = outbound?.enabled !== false;
      if (source.missingClient) {
        missingClientRules.push({ rule, source });
      }
      const sourceInbound = source.inboundId == null ? undefined : lookup.inboundById.get(source.inboundId);
      const sourceInvalidTarget = sourceInbound ? !missingTarget && !outboundSupportsCore(outbound, inboundCore(sourceInbound)) : invalidTarget;
      if (source.clientId != null && isActiveRoutingSource(rule, source, missingTarget, outboundEnabled, sourceInvalidTarget)) {
        explicitlyRoutedClientIds.add(source.clientId);
      }
      if (isActiveRoutingSource(rule, source, missingTarget, outboundEnabled, sourceInvalidTarget) && source.inboundId != null && source.clientId == null) {
        routedInboundIds.add(source.inboundId);
      }
      edges.push(buildRoutingEdge(rule, source, targetId, index, missingTarget, outboundEnabled, ruleHasSpecificInbound(rule), sourceInvalidTarget));
    });
  });

  const directOutbound = visibleOutbounds.find((outbound) => outbound.tag === 'direct');
  if (directOutbound) {
    inbounds
      .filter((inbound) => !routedInboundIds.has(inbound.id))
      .forEach((inbound) => {
        edges.push(buildDefaultDirectEdge(inbound, directOutbound.enabled !== false));
        (inbound.clients || [])
          .filter((client) => !explicitlyRoutedClientIds.has(client.id))
          .forEach((client) => {
            edges.push(buildClientDefaultDirectEdge(client, directOutbound.enabled !== false));
          });
      });
  }

  Array.from(missingInboundTargets.entries()).sort(([left], [right]) => left.localeCompare(right)).forEach(([key, target], index) => {
    nodes.push(buildMissingInboundNode(key, target.title, missingInboundStartY + index * rowGap, target.subtitle));
  });

  missingClientRules.forEach(({ rule, source }, index) => {
    nodes.push(buildMissingClientNode(rule, source, missingInboundStartY + (missingInboundTargets.size + index) * rowGap));
  });

  Array.from(missingOutboundTargets.entries()).sort(([left], [right]) => left.localeCompare(right)).forEach(([tag, target], index) => {
    nodes.push(buildMissingOutboundNode(tag, (outboundCount + index) * outboundGap, target.subtitle));
  });

  return { nodes, edges };
}

function isSystemDirectOutbound(outbound: Pick<Outbound, 'tag'>) {
  return outbound.tag === systemDirectOutboundTag;
}

function isSystemDirectRoutingRule(rule: Pick<RoutingRule, 'outbound_id' | 'outbound_tag'>, systemDirectOutboundIds: Set<number>) {
  return rule.outbound_tag === systemDirectOutboundTag || systemDirectOutboundIds.has(Number(rule.outbound_id || 0));
}

export function buildInboundTagLookup(inbounds: Inbound[]): Map<string, Inbound> {
  const lookup = new Map<string, Inbound>();
  inbounds.forEach((inbound) => {
    const generated = generatedInboundTag(inbound);
    const remark = String(inbound.remark || '').trim();
    lookup.set(generated, inbound);
    if (remark) lookup.set(remark, inbound);
  });
  return lookup;
}

function buildTopologyLookup(inbounds: Inbound[], outbounds: Outbound[]): TopologyLookup {
  const inboundById = new Map<number, Inbound>();
  const clientsByInboundId = new Map<number, Map<number, Client>>();
  const clientInboundById = new Map<number, Inbound>();
  inbounds.forEach((inbound) => {
    inboundById.set(inbound.id, inbound);
    const clients = new Map<number, Client>();
    (inbound.clients || []).forEach((client) => {
      clients.set(client.id, client);
      clientInboundById.set(client.id, inbound);
    });
    clientsByInboundId.set(inbound.id, clients);
  });
  return {
    inboundById,
    inboundByTag: buildInboundTagLookup(inbounds),
    outboundById: buildOutboundIdLookup(outbounds),
    clientsByInboundId,
    clientInboundById,
  };
}

function buildOutboundIdLookup(outbounds: Outbound[]): Map<number, Outbound> {
  return new Map(outbounds.filter((item) => item.id).map((item) => [item.id, item]));
}

function resolveRuleOutbound(rule: Pick<RoutingRule, 'outbound_id'>, outboundById: Map<number, Outbound>) {
  const outboundID = Number(rule.outbound_id || 0);
  if (outboundID > 0) return outboundById.get(outboundID);
  return undefined;
}

function missingOutboundTargetKey(rule: Pick<RoutingRule, 'outbound_id' | 'outbound_tag'>) {
  const outboundID = Number(rule.outbound_id || 0);
  if (outboundID > 0) return `id:${outboundID}`;
  return 'missing-outbound-id';
}

function normalizedInboundTag(rule: Pick<RoutingRule, 'inbound_tag'>) {
  return String(rule.inbound_tag || '').trim();
}

function inboundSourcesForRule(rule: Pick<RoutingRule, 'inbound_id' | 'inbound_tag'>, inbounds: Inbound[], lookup: TopologyLookup): RoutingSource[] {
  const inboundID = Number(rule.inbound_id || 0);
  if (inboundID > 0) {
    const inbound = lookup.inboundById.get(inboundID);
    return inbound
      ? [{
          nodeId: inboundNodeId(inbound),
          edgeKey: String(inbound.id),
          enabled: inbound.enabled !== false,
          inboundId: inbound.id,
        }]
      : [{
          nodeId: missingInboundNodeId(`id:${inboundID}`),
          edgeKey: `missing-id-${inboundID}`,
          enabled: false,
        }];
  }
  const inboundTag = normalizedInboundTag(rule);
  if (!inboundTag) {
    return inbounds.map((inbound) => ({
      nodeId: inboundNodeId(inbound),
      edgeKey: String(inbound.id),
      enabled: inbound.enabled !== false,
      inboundId: inbound.id,
    }));
  }
  const inbound = lookup.inboundByTag.get(inboundTag);
  return inbound
    ? [{
        nodeId: inboundNodeId(inbound),
        edgeKey: String(inbound.id),
        enabled: inbound.enabled !== false,
        inboundId: inbound.id,
      }]
    : [{
        nodeId: missingInboundNodeId(inboundTag),
        edgeKey: `missing-${inboundTag}`,
        enabled: false,
    }];
}

function routingSourcesForRule(rule: RoutingRule, inbounds: Inbound[], lookup: TopologyLookup): RoutingSource[] {
  const clientID = Number(rule.client_id || 0);
  if (!clientID) return inboundSourcesForRule(rule, inbounds, lookup);
  const inboundID = Number(rule.inbound_id || 0);
  if (inboundID > 0) {
    const inbound = lookup.inboundById.get(inboundID);
    const client = inbound ? lookup.clientsByInboundId.get(inbound.id)?.get(clientID) : undefined;
    if (inbound && client) {
      return [{
        nodeId: clientNodeId(client),
        edgeKey: `client-${client.id}`,
        enabled: inbound.enabled !== false && client.enabled !== false,
        inboundId: inbound.id,
        clientId: client.id,
      }];
    }
    return [{
      nodeId: missingClientNodeId(rule),
      edgeKey: `missing-client-${clientID}`,
      enabled: false,
      inboundId: inbound?.id,
      clientId: clientID,
      missingClient: true,
    }];
  }
  const inboundTag = normalizedInboundTag(rule);
  if (!inboundTag) {
    const inbound = lookup.clientInboundById.get(clientID);
    if (inbound) {
      const client = lookup.clientsByInboundId.get(inbound.id)?.get(clientID);
      if (client) {
        return [{
          nodeId: clientNodeId(client),
          edgeKey: `client-${client.id}`,
          enabled: inbound.enabled !== false && client.enabled !== false,
          inboundId: inbound.id,
          clientId: client.id,
        }];
      }
    }
  } else {
    const inbound = lookup.inboundByTag.get(inboundTag);
    const client = inbound ? lookup.clientsByInboundId.get(inbound.id)?.get(clientID) : undefined;
    if (inbound && client) {
      return [{
        nodeId: clientNodeId(client),
        edgeKey: `client-${client.id}`,
        enabled: inbound.enabled !== false && client.enabled !== false,
        inboundId: inbound.id,
        clientId: client.id,
      }];
    }
  }
  return [{
    nodeId: missingClientNodeId(rule),
    edgeKey: `missing-client-${clientID}`,
    enabled: false,
    clientId: clientID,
    missingClient: true,
  }];
}

function ruleHasSpecificInbound(rule: Pick<RoutingRule, 'inbound_id' | 'inbound_tag'>) {
  return Number(rule.inbound_id || 0) > 0 || normalizedInboundTag(rule) !== '';
}

function buildInboundNode(inbound: Inbound, y: number): Node<TopologyNodeData> {
  const generated = generatedInboundTag(inbound);
  return {
    id: inboundNodeId(inbound),
    type: 'topologyNode',
    position: { x: inboundX, y },
    data: {
      kind: 'inbound',
      title: inbound.remark || generated,
      subtitle: generated,
      enabled: inbound.enabled !== false,
      meta: [
        { label: '协议', value: inbound.protocol || '-' },
        { label: '内核', value: coreLabel(inboundCore(inbound)) },
        { label: '端口', value: inbound.port ? String(inbound.port) : '-' },
        { label: '传输', value: inbound.network || 'tcp' },
        { label: '安全', value: inbound.security || 'none' },
        { label: '客户端', value: String((inbound.clients || []).length) },
      ],
    },
  };
}

function buildClientNode(client: Client, inbound: Inbound, y: number): Node<TopologyNodeData> {
  return {
    id: clientNodeId(client),
    type: 'topologyNode',
    position: { x: clientX, y },
    data: {
      kind: 'client',
      title: client.email || `client-${client.id}`,
      subtitle: inbound.remark || generatedInboundTag(inbound),
      enabled: client.enabled !== false,
      meta: [
        { label: '上行', value: formatBytes(client.xray_up ?? client.up ?? 0) },
        { label: '下行', value: formatBytes(client.xray_down ?? client.down ?? 0) },
        { label: '限额', value: client.traffic_limit ? formatBytes(client.traffic_limit) : '不限制' },
      ],
    },
  };
}

function buildOutboundNode(outbound: Outbound, y: number): Node<TopologyNodeData> {
  return {
    id: outboundNodeId(outbound.tag),
    type: 'topologyNode',
    position: { x: outboundX, y },
    data: {
      kind: 'outbound',
      title: outbound.tag,
      subtitle: outbound.remark || undefined,
      enabled: outbound.enabled !== false,
      meta: [
        { label: '协议', value: outbound.protocol || '-' },
        { label: '内核', value: outboundSupportedCores(outbound).map(coreLabel).join(' / ') || '-' },
        { label: '地址', value: outbound.address || '-' },
        { label: '端口', value: outbound.port ? String(outbound.port) : '-' },
      ],
    },
  };
}

function buildMissingInboundNode(key: string, title: string, y: number, subtitle?: string): Node<TopologyNodeData> {
  return {
    id: missingInboundNodeId(key),
    type: 'topologyNode',
    position: { x: inboundX, y },
    data: {
      kind: 'missing-inbound',
      title: title || '未知入站',
      subtitle: subtitle ? `路由引用的入站不存在 · ${subtitle}` : '路由引用的入站不存在',
      enabled: false,
      missing: true,
      meta: [
        { label: '协议', value: '-' },
        { label: '端口', value: '-' },
        { label: '传输', value: '未找到' },
        { label: '安全', value: '-' },
        { label: '客户端', value: '-' },
      ],
    },
  };
}

function buildMissingClientNode(rule: RoutingRule, source: RoutingSource, y: number): Node<TopologyNodeData> {
  const clientID = Number(rule.client_id || source.clientId || 0);
  return {
    id: missingClientNodeId(rule),
    type: 'topologyNode',
    position: { x: clientX, y },
    data: {
      kind: 'missing-client',
      title: rule.client_email || `client-${clientID}`,
      subtitle: '路由引用的客户端不存在',
      enabled: false,
      missing: true,
      meta: [
        { label: '客户端 ID', value: clientID ? String(clientID) : '-' },
        { label: '入站', value: rule.inbound_tag || '-' },
        { label: '状态', value: '未找到' },
      ],
    },
  };
}

function buildMissingOutboundNode(tag: string, y: number, subtitle?: string): Node<TopologyNodeData> {
  return {
    id: outboundNodeId(tag),
    type: 'topologyNode',
    position: { x: outboundX, y },
    data: {
      kind: 'missing-outbound',
      title: tag || '未知出站',
      subtitle: subtitle ? `路由引用的出站不存在 · ${subtitle}` : '路由引用的出站不存在',
      enabled: false,
      missing: true,
      meta: [
        { label: '协议', value: '-' },
        { label: '地址', value: '未找到' },
        { label: '端口', value: '-' },
      ],
    },
  };
}

function buildClientEdge(inbound: Inbound, client: Client): Edge<TopologyEdgeData> {
  return {
    id: `client-${inbound.id}-${client.id}`,
    source: inboundNodeId(inbound),
    target: clientNodeId(client),
    type: 'smoothstep',
    animated: false,
    data: {
      kind: 'client-inherits',
      label: '附属客户端',
      enabled: inbound.enabled !== false && client.enabled !== false,
    },
    style: {
      stroke: '#94a3b8',
      strokeDasharray: '4 4',
      opacity: inbound.enabled !== false && client.enabled !== false ? 0.46 : 0.22,
    },
  };
}

function buildDefaultDirectEdge(inbound: Inbound, directEnabled: boolean): Edge<TopologyEdgeData> {
  const enabled = inbound.enabled !== false && directEnabled;
  return {
    id: `default-direct-${inbound.id}`,
    source: inboundNodeId(inbound),
    target: outboundNodeId('direct'),
    type: 'smoothstep',
    animated: false,
    label: '默认出站',
    data: {
      kind: 'default-direct',
      label: '默认出站',
      enabled,
    },
    style: {
      stroke: '#64748b',
      strokeDasharray: '8 6',
      opacity: enabled ? 0.58 : 0.32,
    },
  };
}

function buildClientDefaultDirectEdge(client: Client, directEnabled: boolean): Edge<TopologyEdgeData> {
  const enabled = client.enabled !== false && directEnabled;
  return {
    id: `default-direct-client-${client.id}`,
    source: clientNodeId(client),
    target: outboundNodeId('direct'),
    type: 'smoothstep',
    animated: false,
    label: '继承默认出站',
    data: {
      kind: 'default-direct',
      label: '继承默认出站',
      enabled,
    },
    style: {
      stroke: '#64748b',
      strokeDasharray: '8 6',
      opacity: enabled ? 0.42 : 0.24,
    },
  };
}

function buildRoutingEdge(rule: RoutingRule, source: RoutingSource, targetId: string, index: number, missingTarget: boolean, outboundEnabled: boolean, explicitInbound: boolean, invalidTarget: boolean): Edge<TopologyEdgeData> {
  const enabled = isActiveRoutingSource(rule, source, missingTarget, outboundEnabled, invalidTarget);
  const kind: TopologyEdgeKind = source.clientId != null ? 'client-routing' : explicitInbound ? 'routing' : 'all-inbounds-routing';
  return {
    id: `rule-${rule.id}-${source.edgeKey}-${index}`,
    source: source.nodeId,
    target: targetId,
    type: 'smoothstep',
    animated: enabled,
    label: routeEdgeLabel(rule, explicitInbound),
    data: {
      kind,
      label: routeEdgeLabel(rule, explicitInbound),
      enabled,
      ruleId: rule.id,
      missingTarget,
      invalidTarget,
    },
    style: {
      stroke: missingTarget || invalidTarget ? '#dc2626' : enabled ? '#0f766e' : '#94a3b8',
      strokeDasharray: enabled ? undefined : '6 5',
      opacity: enabled ? 0.82 : 0.36,
    },
  };
}

function isActiveRoutingSource(rule: Pick<RoutingRule, 'enabled'>, source: RoutingSource, missingTarget: boolean, outboundEnabled: boolean, invalidTarget = false) {
  return rule.enabled !== false && source.enabled && outboundEnabled && !missingTarget && !invalidTarget;
}

function sourcesForCoreCheck(rule: RoutingRule, inbounds: Inbound[], lookup: TopologyLookup) {
  return routingSourcesForRule(rule, inbounds, lookup).filter((source) => source.inboundId != null);
}

function routeEdgeLabel(rule: RoutingRule, explicitInbound: boolean) {
  if (Number(rule.client_id || 0) > 0) {
    const prefix = `#${rule.id} 客户端`;
    return rule.enabled === false ? `${prefix} 禁用` : prefix;
  }
  const prefix = explicitInbound ? `#${rule.id}` : `#${rule.id} 全部入站`;
  return rule.enabled === false ? `${prefix} 禁用` : prefix;
}

function inboundNodeId(inbound: Pick<Inbound, 'id'>) {
  return `inbound:${inbound.id}`;
}

function missingInboundNodeId(tag: string) {
  return `inbound-missing:${tag || 'unknown'}`;
}

function missingClientNodeId(rule: Pick<RoutingRule, 'id' | 'client_id'>) {
  return `client-missing:${rule.id}`;
}

function clientNodeId(client: Pick<Client, 'id'>) {
  return `client:${client.id}`;
}

function outboundNodeId(tag: string) {
  return `outbound:${tag || 'unknown'}`;
}
