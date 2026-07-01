import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import type { EChartsOption } from 'echarts';
import { Activity, AlertTriangle, BarChart3, Cpu, Database, HardDrive, Network, RefreshCw, Shield, Users } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { appPath, getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import { trafficV2StreamPath } from '../api/traffic';
import type { DashboardSummary, TrafficV2AnalyticsPoint, TrafficV2AnalyticsRank, TrafficV2AnalyticsResponse, TrafficV2Metric, TrafficV2Patch, TrafficV2Realtime, TrafficV2Snapshot } from '../api/types';
import { Card, LoadingBlock } from '../components/ui';
import { formatBytes, formatDuration, formatPercent, serviceLabel, versionLabel } from '../lib/format';
import { useI18n } from '../lib/i18n';
import { invalidateTrafficV2Snapshot, refreshQueries } from '../lib/queryInvalidation';
import { usePageVisible } from '../lib/visibility';

export default function OverviewPage() {
  const visible = usePageVisible();
  const { text } = useI18n();
  const [trafficRange, setTrafficRange] = useState<TrafficAnalyticsRange>('24h');
  const [trafficMetric, setTrafficMetric] = useState<TrafficAnalyticsMetric>('usage');
  const [trafficScope, setTrafficScope] = useState<TrafficAnalyticsScope>('inbound');
  const [trafficChartMode, setTrafficChartMode] = useState<TrafficChartMode>('area');
  const [showDetails, setShowDetails] = useState(false);
  useEffect(() => {
    if (trafficMetric === 'rate' && trafficChartMode === 'heatmap') {
      setTrafficChartMode('area');
    }
  }, [trafficChartMode, trafficMetric]);
  const summary = useQuery({ queryKey: ['dashboard-summary'], queryFn: api.dashboardSummary, refetchInterval: visible ? 15000 : false, retry: false, staleTime: 10_000 });
  const trafficSnapshot = useQuery({ queryKey: ['traffic-v2-snapshot'], queryFn: api.trafficV2Snapshot, refetchInterval: visible ? 15000 : false, retry: false, staleTime: 10_000 });
  const trafficAnalyticsQuery = useQuery({
    queryKey: ['traffic-v2-analytics', trafficRange, trafficMetric, trafficScope],
    queryFn: () => api.trafficV2Analytics({ range: trafficRange, metric: trafficMetric, scope_type: trafficScope, top: 5 }),
    refetchInterval: visible ? 30000 : false,
    retry: false,
    staleTime: 20_000,
  });
  const resources = useQuery({ queryKey: ['resources'], queryFn: api.resources, refetchInterval: visible ? 10000 : false, staleTime: 5_000 });
  const [xray, singbox] = useQueries({
    queries: [
      { queryKey: ['xray-status'], queryFn: api.xrayStatus, refetchInterval: visible ? 15000 : false, staleTime: 10_000 },
      { queryKey: ['singbox-status'], queryFn: api.singboxStatus, refetchInterval: visible ? 15000 : false, staleTime: 10_000 },
    ],
  });

  const data = summary.data;
  const counts = data?.counts || emptyCounts;
  const traffic = trafficSnapshot.data || emptyTrafficV2;
  const totalCumulative = traffic.total.cumulative;
  const totalRealtime = traffic.total.realtime;
  useTrafficStream(visible);
  const trafficStatus = traffic.coverage;
  const protocols = Object.entries(data?.protocols || {}).map(([name, value]) => ({ name, value }));
  const trafficLoading = trafficSnapshot.isLoading && !trafficSnapshot.data;
  const trafficUnavailable = trafficSnapshot.isError && !trafficSnapshot.data;
  const trafficHidden = trafficLoading || trafficUnavailable;
  const trafficPlaceholder = trafficLoading ? text('加载中') : text('不可用');
  const trafficPlaceholderSub = trafficLoading ? text('等待流量摘要') : text('查看告警');
  const trafficAnalyticsLoading = trafficAnalyticsQuery.isLoading && !trafficAnalyticsQuery.data;

  if (summary.isLoading) return <LoadingBlock />;

  return (
    <div className="page-stack">
      <PageTitle
        title={text('运行概览')}
        description={text('VPS 面板、核心服务和业务累计用量的摘要。')}
        action={<button className="btn secondary" onClick={() => refreshOverview([summary, trafficSnapshot, trafficAnalyticsQuery, resources, xray, singbox])}><RefreshCw className="h-4 w-4" /> {text('刷新')}</button>}
      />
      <OverviewAlerts
        errors={[
          summary.error ? `${text('概览摘要加载失败')}：${errorText(summary.error)}` : '',
          trafficSnapshot.error ? `${text('流量摘要加载失败')}：${errorText(trafficSnapshot.error)}` : '',
          trafficAnalyticsQuery.error ? `${text('流量分析加载失败')}：${errorText(trafficAnalyticsQuery.error)}` : '',
          resources.error ? `${text('资源加载失败')}：${errorText(resources.error)}` : '',
          xray.error ? `Xray ${text('状态加载失败')}：${errorText(xray.error)}` : '',
          singbox.error ? `sing-box ${text('状态加载失败')}：${errorText(singbox.error)}` : '',
          data?.validation.xray && !data.validation.xray.valid ? `Xray ${text('生成校验失败')}：${data.validation.xray.error || text('未知错误')}` : '',
          data?.validation.singbox && !data.validation.singbox.valid ? `sing-box ${text('生成校验失败')}：${data.validation.singbox.error || text('未知错误')}` : '',
        ].filter(Boolean)}
      />
      <div className="metric-grid">
        <Metric icon={Network} tone="teal" label={text('总流量')} value={trafficHidden ? trafficPlaceholder : formatBytes(totalCumulative.total)} sub={trafficHidden ? trafficPlaceholderSub : `${formatBytes(totalCumulative.up)} ↑ / ${formatBytes(totalCumulative.down)} ↓`} title={trafficHint(traffic.observed_at, totalRealtime.window_seconds, totalCumulative.source, totalCumulative.status, totalCumulative.message, text)} />
        <Metric
          icon={Activity}
          tone={trafficLoading ? 'slate' : trafficUnavailable ? 'rose' : trafficStatusTone(trafficStatus?.overall)}
          label={text('总实时流量')}
          value={trafficHidden ? trafficPlaceholder : realtimeTotalLabel(totalRealtime.rate_total, totalRealtime.status, text)}
          sub={trafficHidden ? trafficPlaceholderSub : trafficRateSummary(totalRealtime.rate_up, totalRealtime.rate_down, totalRealtime.status || trafficStatus?.overall, trafficStatus?.engines, text)}
          title={trafficHint(totalRealtime.observed_at || traffic.observed_at, totalRealtime.window_seconds, totalRealtime.source, totalRealtime.status, totalRealtime.message, text)}
        />
        <Metric icon={Users} tone="blue" label={text('节点/客户端')} value={`${counts.inbounds}/${counts.clients}`} sub={`${counts.inbounds_enabled} ${text('节点已启用')} · ${counts.clients_active} ${text('客户端活跃')}`} />
        <Metric icon={Shield} tone={coreStatusTone(xray.data?.status, singbox.data?.status)} label={text('核心状态')} value={coreStatusValue(xray.data?.status, singbox.data?.status, text)} sub={`Xray ${text(serviceLabel(xray.data?.status))} · sing-box ${text(serviceLabel(singbox.data?.status))}`} />
      </div>
      <button className="btn secondary overview-details-toggle" onClick={() => setShowDetails((value) => !value)}>
        {text(showDetails ? '收起运行详情' : '更多运行详情')}
      </button>
      {showDetails ? (
        <Card className="p-5">
          <h2 className="section-title mb-4">{text('最近生成状态')}</h2>
          <div className="grid gap-3 md:grid-cols-2">
            <ValidationSummary label="Xray" loading={summary.isLoading} valid={data?.validation.xray.valid} error={summary.error} detail={validationSummary(data?.validation.xray, text, summary.error)} />
            <ValidationSummary label="sing-box" loading={summary.isLoading} valid={data?.validation.singbox.valid} error={summary.error} detail={validationSummary(data?.validation.singbox, text, summary.error)} />
          </div>
        </Card>
      ) : null}
      <div className="dashboard-monitor-grid">
        <TrafficAnalyticsCard
          data={trafficAnalyticsQuery.data}
          loading={trafficAnalyticsLoading}
          range={trafficRange}
          metric={trafficMetric}
          scope={trafficScope}
          mode={trafficChartMode}
          onRangeChange={setTrafficRange}
          onMetricChange={setTrafficMetric}
          onScopeChange={setTrafficScope}
          onModeChange={setTrafficChartMode}
        />
        <RuntimeStatusPanel
          resources={resources.data}
        />
      </div>
      {showDetails ? (
        <Card className="p-5">
          <h2 className="section-title mb-4">{text('协议分布')}</h2>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {protocols.length ? protocols.map((item) => <div key={item.name} className="rounded-lg bg-panel-soft p-3 text-sm"><b>{item.name}</b><span className="ml-2 text-panel-muted">{item.value}</span></div>) : <span className="text-sm text-panel-muted">{text('暂无入站')}</span>}
          </div>
        </Card>
      ) : null}
    </div>
  );
}

const emptyCounts: DashboardSummary['counts'] = {
  inbounds: 0,
  inbounds_enabled: 0,
  clients: 0,
  clients_active: 0,
  clients_expired: 0,
  clients_limited: 0,
  outbounds: 0,
  outbounds_enabled: 0,
  routing_rules: 0,
  routing_enabled: 0,
};

const emptyTrafficMetric: TrafficV2Metric = {
  up: 0,
  down: 0,
  total: 0,
  status: 'waiting',
  source: 'migate',
  message: '',
};

const emptyTrafficRealtime: TrafficV2Realtime = {
  delta_up: 0,
  delta_down: 0,
  delta_total: 0,
  rate_up: 0,
  rate_down: 0,
  rate_total: 0,
  observed_at: '',
  window_seconds: 0,
  status: 'waiting',
  source: 'inbound',
  message: '',
};

const emptyTrafficV2: TrafficV2Snapshot = {
  generated_at: '',
  observed_at: '',
  window_seconds: 0,
  total: { cumulative: emptyTrafficMetric, realtime: emptyTrafficRealtime },
  inbounds: [],
  clients: [],
  coverage: { overall: 'waiting', engines: { xray: 'not_configured', singbox: 'not_configured' }, ok: 0, waiting: 0, stale: 0, unavailable: 0, unsupported: 0, partial: 0 },
};

type TrafficAnalyticsRange = '1h' | '24h' | '7d' | '30d';
type TrafficAnalyticsMetric = 'usage' | 'rate' | 'cumulative';
type TrafficAnalyticsScope = 'inbound' | 'client';
type TrafficChartMode = 'area' | 'bar' | 'rank' | 'heatmap';

const trafficRanges: TrafficAnalyticsRange[] = ['1h', '24h', '7d', '30d'];
const trafficMetrics: TrafficAnalyticsMetric[] = ['usage', 'rate', 'cumulative'];
const trafficScopes: TrafficAnalyticsScope[] = ['inbound', 'client'];
const trafficChartModes: TrafficChartMode[] = ['area', 'bar', 'rank', 'heatmap'];

export function useTrafficStream(enabled: boolean) {
  const queryClient = useQueryClient();
  const lastErrorInvalidateAt = useRef(0);
  useEffect(() => {
    if (!enabled || typeof EventSource === 'undefined') return;
    const source = new EventSource(appPath(trafficV2StreamPath));
    const handleSnapshot = (event: Event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data || '{}') as TrafficV2Snapshot;
        if (payload.total && Array.isArray(payload.inbounds) && Array.isArray(payload.clients)) {
          queryClient.setQueryData(['traffic-v2-snapshot'], payload);
        }
      } catch {
        // REST polling remains the fallback if a streaming frame is malformed.
      }
    };
    const handlePatch = (event: Event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data || '{}') as TrafficV2Patch;
        queryClient.setQueryData(['traffic-v2-snapshot'], (current: TrafficV2Snapshot | undefined) => mergeTrafficV2Snapshot(current, payload));
      } catch {
        // REST polling remains the fallback if a streaming frame is malformed.
      }
    };
    const invalidateSnapshotOnError = () => {
      if (queryClient.isFetching({ queryKey: ['traffic-v2-snapshot'] }) > 0) return;
      const now = Date.now();
      if (now - lastErrorInvalidateAt.current < 5000) return;
      lastErrorInvalidateAt.current = now;
      invalidateTrafficV2Snapshot(queryClient);
    };
    source.addEventListener('snapshot', handleSnapshot);
    source.addEventListener('patch', handlePatch);
    source.addEventListener('delta', handlePatch);
    source.addEventListener('stream-error', invalidateSnapshotOnError);
    source.addEventListener('error', invalidateSnapshotOnError);
    return () => {
      source.removeEventListener('snapshot', handleSnapshot);
      source.removeEventListener('patch', handlePatch);
      source.removeEventListener('delta', handlePatch);
      source.removeEventListener('stream-error', invalidateSnapshotOnError);
      source.removeEventListener('error', invalidateSnapshotOnError);
      source.close();
    };
  }, [enabled, queryClient]);
}

export function mergeTrafficV2Snapshot(current: TrafficV2Snapshot | undefined, patch: TrafficV2Patch): TrafficV2Snapshot {
  const base = current || emptyTrafficV2;
  return {
    generated_at: patch.generated_at ?? base.generated_at,
    observed_at: patch.observed_at ?? base.observed_at,
    window_seconds: patch.window_seconds ?? base.window_seconds,
    total: patch.total || base.total,
    inbounds: mergeTrafficV2ById(base.inbounds, patch.inbounds, patch.removed_inbound_ids),
    clients: mergeTrafficV2ById(base.clients, patch.clients, patch.removed_client_ids),
    coverage: patch.coverage || base.coverage,
  };
}

function mergeTrafficV2ById<T extends { id: number }>(current: T[], updates?: T[], removedIDs?: number[]) {
  if ((!updates || updates.length === 0) && (!removedIDs || removedIDs.length === 0)) return current;
  const nextUpdates = updates || [];
  const removed = new Set(removedIDs || []);
  const byID = new Map(current.filter((item) => !removed.has(item.id)).map((item) => [item.id, item]));
  for (const update of nextUpdates) {
    byID.set(update.id, update);
  }
  const merged = current.filter((item) => !removed.has(item.id)).map((item) => byID.get(item.id) || item);
  const seen = new Set(merged.map((item) => item.id));
  for (const update of nextUpdates) {
    if (!seen.has(update.id)) {
      merged.push(update);
    }
  }
  return merged;
}

function OverviewAlerts({ errors }: { errors: string[] }) {
  if (errors.length === 0) return null;
  return (
    <Card className="border-red-200 bg-red-50 p-4 text-sm text-red-700">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-4 w-4" />
        <div className="grid gap-1">
          {errors.map((error) => <div key={error}>{error}</div>)}
        </div>
      </div>
    </Card>
  );
}

function TrafficAnalyticsCard({
  data,
  loading,
  range,
  metric,
  scope,
  mode,
  onRangeChange,
  onMetricChange,
  onScopeChange,
  onModeChange,
}: {
  data?: TrafficV2AnalyticsResponse;
  loading?: boolean;
  range: TrafficAnalyticsRange;
  metric: TrafficAnalyticsMetric;
  scope: TrafficAnalyticsScope;
  mode: TrafficChartMode;
  onRangeChange: (value: TrafficAnalyticsRange) => void;
  onMetricChange: (value: TrafficAnalyticsMetric) => void;
  onScopeChange: (value: TrafficAnalyticsScope) => void;
  onModeChange: (value: TrafficChartMode) => void;
}) {
  const { text } = useI18n();
  const availableModes = metric === 'rate' ? trafficChartModes.filter((item) => item !== 'heatmap') : trafficChartModes;
  const effectiveMode = metric === 'rate' && mode === 'heatmap' ? 'area' : mode;
  const option = useMemo(() => buildTrafficAnalyticsOption(data, effectiveMode, metric, scope, text), [data, effectiveMode, metric, scope, text]);
  const summary = data?.summary;
  const valueLabel = metric === 'rate' ? `${formatBytes(summary?.rate_total || 0)}/s` : formatBytes(summary?.total || 0);
  const upLabel = metric === 'rate' ? `${formatBytes(summary?.rate_up || 0)}/s` : formatBytes(summary?.up || 0);
  const downLabel = metric === 'rate' ? `${formatBytes(summary?.rate_down || 0)}/s` : formatBytes(summary?.down || 0);
  const peakLabel = metric === 'rate' ? `${formatBytes(summary?.peak_rate || 0)}/s` : formatBytes(summary?.peak_total || 0);
  const totalLabel = metric === 'rate' ? `${formatBytes(summary?.rate_total || 0)}/s` : formatBytes(summary?.total || 0);
  const pointsLabel = summary?.points != null ? String(summary.points) : '-';
  return (
    <Card className="traffic-analytics-card">
      <div className="traffic-analytics-header">
        <div className="traffic-analytics-title">
          <div className="traffic-analytics-kicker"><BarChart3 className="h-4 w-4" /> {text('流量分析')}</div>
          <h2>{summary?.has_data ? valueLabel : text('等待采样')}</h2>
          <p>{trafficAnalyticsSubtitle(data, metric, text)}</p>
        </div>
        <div className="traffic-analytics-controls">
          <div className="traffic-control-row traffic-control-row-primary">
            <Segmented values={trafficRanges} value={range} label={(value) => text(trafficRangeLabel(value))} onChange={onRangeChange} />
            <Segmented values={trafficScopes} value={scope} label={(value) => text(value === 'client' ? '客户端' : '入站')} onChange={onScopeChange} />
          </div>
          <div className="traffic-control-row traffic-control-row-secondary">
            <Segmented values={trafficMetrics} value={metric} label={(value) => text(trafficMetricLabel(value))} onChange={onMetricChange} />
            <Segmented values={availableModes} value={effectiveMode} label={(value) => text(trafficModeLabel(value))} onChange={onModeChange} />
          </div>
        </div>
      </div>
      <div className="traffic-meta-tags">
        <InfoTag label={text('采样粒度')} value={formatBucketSeconds(data?.bucket_seconds || 0)} />
        <InfoTag label={text('数据点')} value={pointsLabel} />
        <InfoTag label={text('峰值时间')} value={summary?.peak_at ? formatAxisTime(summary.peak_at, data?.range) : text('未知')} />
        <InfoTag label={text('维度')} value={text(scope === 'client' ? '客户端' : '入站')} />
      </div>
      <div className="traffic-stat-strip">
        <InlineStat label={text('上传')} value={upLabel} tone="up" />
        <InlineStat label={text('下载')} value={downLabel} tone="down" />
        <InlineStat label={text('峰值')} value={peakLabel} tone="peak" />
        <InlineStat label={text('总量')} value={totalLabel} tone="muted" />
      </div>
      <div className="traffic-chart-shell">
        {loading ? (
          <div className="traffic-chart-empty">{text('流量分析加载中')}</div>
        ) : !data?.summary?.has_data ? (
          <div className="traffic-chart-empty">{text('暂无流量数据')}</div>
        ) : (
          <EChartsView option={option} />
        )}
      </div>
      <TrafficInsightTags data={data} metric={metric} />
    </Card>
  );
}

function InfoTag({ label, value }: { label: string; value: string }) {
  return <span className="info-tag"><span>{label}</span><b>{value}</b></span>;
}

function InlineStat({ label, value, tone }: { label: string; value: string; tone: 'up' | 'down' | 'peak' | 'muted' }) {
  return <span className={`inline-stat inline-stat-${tone}`}><span>{label}</span><b>{value}</b></span>;
}

function TrafficInsightTags({ data, metric }: { data?: TrafficV2AnalyticsResponse; metric: TrafficAnalyticsMetric }) {
  const { text } = useI18n();
  const summary = data?.summary;
  if (!summary?.has_data) return null;
  const total = metric === 'rate' ? summary.rate_total || 0 : summary.total || 0;
  const up = metric === 'rate' ? summary.rate_up || 0 : summary.up || 0;
  const down = metric === 'rate' ? summary.rate_down || 0 : summary.down || 0;
  const upPercent = total > 0 ? Math.round((up / total) * 100) : 0;
  const downPercent = total > 0 ? Math.max(0, 100 - upPercent) : 0;
  const client = data?.top_clients?.[0];
  const inbound = data?.top_inbounds?.[0];
  return (
    <div className="traffic-insight-tags">
      <InfoTag label={text('上传占比')} value={`${upPercent}%`} />
      <InfoTag label={text('下载占比')} value={`${downPercent}%`} />
      {client ? <InfoTag label={text('Top 客户端')} value={client.label || client.scope_key || `#${client.id}`} /> : null}
      {inbound ? <InfoTag label={text('Top 入站')} value={inbound.label || inbound.scope_key || `#${inbound.id}`} /> : null}
    </div>
  );
}

function Segmented<T extends string>({ values, value, label, onChange }: { values: T[]; value: T; label: (value: T) => string; onChange: (value: T) => void }) {
  return (
    <div className="traffic-segmented">
      {values.map((item) => (
        <button key={item} className={item === value ? 'active' : ''} type="button" onClick={() => onChange(item)}>
          {label(item)}
        </button>
      ))}
    </div>
  );
}

function EChartsView({ option }: { option: EChartsOption }) {
  const elementRef = useRef<HTMLDivElement | null>(null);
  const optionRef = useRef(option);
  optionRef.current = option;
  useEffect(() => {
    if (!elementRef.current) return;
    let disposed = false;
    let chart: import('echarts').ECharts | undefined;
    let observer: ResizeObserver | undefined;
    const resize = () => chart?.resize();
    void import('echarts').then((echarts) => {
      if (disposed || !elementRef.current) return;
      chart = echarts.init(elementRef.current, undefined, { renderer: 'canvas' });
      chart.setOption(optionRef.current, true);
      window.addEventListener('resize', resize);
      if (typeof ResizeObserver !== 'undefined') {
        observer = new ResizeObserver(resize);
        observer.observe(elementRef.current);
      }
    });
    return () => {
      disposed = true;
      observer?.disconnect();
      window.removeEventListener('resize', resize);
      chart?.dispose();
    };
  }, []);
  useEffect(() => {
    if (!elementRef.current) return;
    void import('echarts').then((echarts) => {
      const chart = elementRef.current ? echarts.getInstanceByDom(elementRef.current) : undefined;
      chart?.setOption(option, true);
    });
  }, [option]);
  return <div ref={elementRef} className="traffic-echart" role="img" aria-label="traffic analytics chart" />;
}

export function buildTrafficAnalyticsOption(data: TrafficV2AnalyticsResponse | undefined, mode: TrafficChartMode, metric: TrafficAnalyticsMetric, scope: TrafficAnalyticsScope, text: (value: string) => string): EChartsOption {
  const series = data?.series || [];
  const axis = series.map((point) => formatAxisTime(point.time, data?.range));
  const valueFor = (point: TrafficV2AnalyticsPoint, key: 'up' | 'down' | 'total') => metric === 'rate' ? point[`rate_${key}` as 'rate_up' | 'rate_down' | 'rate_total'] : point[key];
  const formatValue = (value: number) => metric === 'rate' ? `${formatBytes(value)}/s` : formatBytes(value);
  const rankValueFor = (item: TrafficV2AnalyticsRank) => metric === 'rate' ? Number(item.rate_total ?? item.total ?? 0) : Number(item.total ?? 0);
  const values = series.flatMap((point) => [valueFor(point, 'up'), valueFor(point, 'down'), valueFor(point, 'total')]);
  const hasPositiveValue = values.some((value) => Number(value) > 0);
  const yAxisMax = hasPositiveValue ? undefined : 1;
  if (mode === 'heatmap') {
    const heatmap = data?.heatmap || [];
    const heatmapValueFor = (item: (typeof heatmap)[number]) => metric === 'rate' ? Number(item.rate_total ?? item.total ?? 0) : Number(item.total ?? 0);
    const days = Array.from(new Set(heatmap.map((item) => item.day)));
    const hours = Array.from({ length: 24 }, (_, index) => `${String(index).padStart(2, '0')}:00`);
    return {
      color: ['#0f766e'],
      grid: { left: 58, right: 18, top: 20, bottom: 46 },
      tooltip: { position: 'top', valueFormatter: (value) => formatValue(Number(value || 0)) },
      xAxis: { type: 'category', data: days, splitArea: { show: true }, axisTick: { show: false } },
      yAxis: { type: 'category', data: hours, splitArea: { show: true }, axisTick: { show: false } },
      visualMap: { min: 0, max: Math.max(1, ...heatmap.map(heatmapValueFor)), calculable: true, orient: 'horizontal', left: 'center', bottom: 0, formatter: (value) => formatValue(Number(value || 0)) },
      series: [{ type: 'heatmap', data: heatmap.map((item) => [item.day, `${String(item.hour).padStart(2, '0')}:00`, heatmapValueFor(item)]), emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(15, 23, 42, 0.2)' } } }],
    };
  }
  if (mode === 'rank') {
    const ranks = scope === 'client' ? data?.top_clients || [] : data?.top_inbounds || [];
    return {
      color: ['#2563eb'],
      grid: { left: 12, right: 28, top: 18, bottom: 18, containLabel: true },
      tooltip: { trigger: 'axis', valueFormatter: (value) => formatValue(Number(value || 0)) },
      xAxis: { type: 'value', axisLabel: { formatter: (value: number) => formatValue(value) }, splitLine: { lineStyle: { color: 'rgba(148,163,184,0.18)' } } },
      yAxis: { type: 'category', data: ranks.map((item) => item.label || item.scope_key || `#${item.id}`), axisTick: { show: false } },
      series: [{ type: 'bar', data: ranks.map(rankValueFor), barMaxWidth: 16, itemStyle: { borderRadius: [0, 7, 7, 0] } }],
    };
  }
  return {
    color: ['#0f766e', '#2563eb', '#f59e0b'],
    legend: { top: 0, right: 0, icon: 'roundRect', textStyle: { color: '#64748b' } },
    grid: { left: 10, right: 18, top: 42, bottom: mode === 'area' ? 58 : 36, containLabel: true },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'cross', label: { backgroundColor: '#0f172a' } },
      valueFormatter: (value) => formatValue(Number(value || 0)),
    },
    dataZoom: mode === 'area' ? [{ type: 'inside' }, { type: 'slider', height: 16, bottom: 12, borderColor: 'transparent', fillerColor: 'rgba(37,99,235,0.12)', handleSize: 14 }] : [{ type: 'inside' }],
    xAxis: { type: 'category', boundaryGap: mode === 'bar', data: axis, axisTick: { show: false }, axisLine: { lineStyle: { color: 'rgba(148,163,184,0.35)' } } },
    yAxis: { type: 'value', min: 0, max: yAxisMax, minInterval: metric === 'rate' ? undefined : 1, axisLabel: { formatter: (value: number) => formatValue(value) }, splitLine: { lineStyle: { color: 'rgba(148,163,184,0.18)' } } },
    series: [
      {
        name: text('上传'),
        type: mode === 'bar' ? 'bar' : 'line',
        stack: mode === 'bar' ? 'traffic' : undefined,
        smooth: mode !== 'bar',
        showSymbol: false,
        areaStyle: mode === 'area' ? { opacity: 0.18 } : undefined,
        data: series.map((point) => valueFor(point, 'up')),
        markPoint: { data: [{ type: 'max', name: text('峰值') }], symbolSize: 42 },
      },
      {
        name: text('下载'),
        type: mode === 'bar' ? 'bar' : 'line',
        stack: mode === 'bar' ? 'traffic' : undefined,
        smooth: mode !== 'bar',
        showSymbol: false,
        areaStyle: mode === 'area' ? { opacity: 0.14 } : undefined,
        data: series.map((point) => valueFor(point, 'down')),
      },
      {
        name: text('总量'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 2, type: metric === 'cumulative' ? 'solid' : 'dashed' },
        data: series.map((point) => valueFor(point, 'total')),
        markLine: { data: [{ type: 'average', name: text('平均') }], symbol: 'none' },
      },
    ],
  };
}

function trafficAnalyticsSubtitle(data: TrafficV2AnalyticsResponse | undefined, metric: TrafficAnalyticsMetric, text: (value: string) => string) {
  if (!data?.summary?.has_data) return text('至少需要采样数据后才能绘制趋势');
  const peakAt = data.summary.peak_at ? formatAxisTime(data.summary.peak_at, data.range) : text('未知');
  const suffix = data.semantics === 'historical_samples' ? ` · ${text('重置累计不会改写历史趋势')}` : '';
  return `${text(trafficMetricLabel(metric))} · ${text('峰值')} ${formatBytes(metric === 'rate' ? data.summary.peak_rate : data.summary.peak_total)}${metric === 'rate' ? '/s' : ''} · ${peakAt}${suffix}`;
}

function RuntimeStatusPanel({
  resources,
}: {
  resources?: { cpu_percent?: number; memory_used?: number; memory_total?: number; disk_used?: number; disk_total?: number; uptime_seconds?: number };
}) {
  const { text } = useI18n();
  return (
    <Card className="runtime-status-card">
      <div className="runtime-status-header">
        <div>
          <h2>{text('服务器资源')}</h2>
        </div>
        <Activity className="h-5 w-5" />
      </div>
      <div className="runtime-resource-grid">
        <Resource icon={Cpu} tone="blue" label="CPU" value={formatPercent(resources?.cpu_percent)} />
        <Resource icon={Database} tone="violet" label={text('内存')} value={`${formatBytes(resources?.memory_used)} / ${formatBytes(resources?.memory_total)}`} />
        <Resource icon={HardDrive} tone="amber" label={text('磁盘')} value={`${formatBytes(resources?.disk_used)} / ${formatBytes(resources?.disk_total)}`} />
        <Resource icon={Activity} tone="teal" label={text('运行时间')} value={formatDuration(resources?.uptime_seconds)} />
      </div>
    </Card>
  );
}

function trafficRangeLabel(value: TrafficAnalyticsRange) {
  return value === '1h' ? '1小时' : value === '24h' ? '24小时' : value === '7d' ? '7天' : '30天';
}

function trafficMetricLabel(value: TrafficAnalyticsMetric) {
  return value === 'usage' ? '区间用量' : value === 'rate' ? '实时速率' : '累计总量';
}

function trafficModeLabel(value: TrafficChartMode) {
  return value === 'area' ? '趋势' : value === 'bar' ? '堆叠' : value === 'rank' ? '排行' : '热力';
}

function formatBucketSeconds(seconds: number) {
  if (!seconds) return '-';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}min`;
  return `${Math.round(seconds / 3600)}h`;
}

function formatAxisTime(value: string | undefined, range?: string) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  if (range === '1h' || range === '24h') {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return date.toLocaleDateString([], { month: '2-digit', day: '2-digit' });
}

function ValidationSummary({ label, loading, valid, error, detail }: { label: string; loading: boolean; valid?: boolean; error: unknown; detail: string }) {
  const { text } = useI18n();
  const failed = Boolean(error) || valid === false;
  const tone = loading ? 'text-panel-muted' : failed ? 'text-red-700' : valid === true ? 'text-emerald-700' : 'text-panel-muted';
  return (
    <div className="rounded-lg bg-panel-soft p-3 text-sm">
      <div className="flex items-center justify-between gap-3">
        <span className="font-medium">{label}</span>
        <span className={tone}>{validationStatusLabel({ loading, valid, error }, text)}</span>
      </div>
      <div className="mt-2 text-xs leading-5 text-panel-muted">{detail}</div>
    </div>
  );
}

export function validationStatusLabel(state: { loading: boolean; valid?: boolean; error?: unknown }, text: (value: string) => string) {
  if (state.loading) return text('生成中');
  if (state.error) return text('不可用');
  if (state.valid === false) return text('失败');
  if (state.valid === true) return text('通过');
  return text('未知');
}

export function validationSummary(data: { valid: boolean; inbounds?: number; outbounds?: number; rules?: number; warnings?: string[]; error?: string } | undefined, text: (value: string) => string, error?: unknown) {
  if (error) return errorText(error);
  if (!data) return text('等待校验结果');
  const parts = [];
  if (data.inbounds != null) parts.push(`inbounds ${data.inbounds}`);
  if (data.outbounds != null) parts.push(`outbounds ${data.outbounds}`);
  if (data.rules != null) parts.push(`rules ${data.rules}`);
  if (data.warnings?.length) parts.push(`warnings ${data.warnings.length}`);
  if (data.error) parts.push(data.error);
  return parts.join(' · ');
}

function errorText(error: unknown) {
  return getAPIErrorMessage(error, 'unknown');
}

export function trafficStatusLabel(status: string | undefined, text: (value: string) => string) {
  if (status === 'ok') return text('统计正常');
  if (status === 'partial') return text('统计覆盖不完整');
  if (status === 'unsupported') return text('当前 sing-box 二进制不支持实时统计');
  if (status === 'not_configured') return text('未配置对应核心入站');
  if (status === 'unavailable') return text('统计接口不可用');
  if (status === 'stale') return text('统计状态过期');
  if (status === 'cumulative_only') return text('仅显示累计');
  return text('等待采样');
}

function trafficStatusTone(status?: string): MetricTone {
  if (status === 'ok') return 'emerald';
  if (status === 'waiting' || status === 'partial') return 'amber';
  if (status === 'unavailable' || status === 'stale') return 'rose';
  return 'slate';
}

function coreStatusTone(xrayStatus?: string, singboxStatus?: string): MetricTone {
  if (xrayStatus === 'running' && singboxStatus === 'running') return 'emerald';
  if (xrayStatus === 'running' || singboxStatus === 'running') return 'amber';
  return 'rose';
}

function coreStatusValue(xrayStatus: string | undefined, singboxStatus: string | undefined, text: (value: string) => string) {
  if (xrayStatus === 'running' && singboxStatus === 'running') return text('运行正常');
  if (xrayStatus === 'running' || singboxStatus === 'running') return text('部分运行');
  return text('未运行');
}

export function engineStatusSummary(engines: Record<string, string> | undefined, text: (value: string) => string) {
  if (!engines) return text('等待采样');
  return Object.entries(engines).map(([engine, status]) => `${engine}: ${trafficStatusLabel(status, text)}`).join(' · ');
}

export function trafficRateSummary(rateUp: number, rateDown: number, status: string | undefined, engines: Record<string, string> | undefined, text: (value: string) => string) {
  const statusLabel = trafficStatusLabel(status, text);
  if (!status || status === 'ok') {
    return `${realtimeRateLabel(rateUp, rateDown)} · ${statusLabel}`;
  }
  return `${statusLabel} · ${engineStatusSummary(engines, text)}`;
}

export function realtimeRateLabel(rateUp: unknown, rateDown: unknown) {
  return `${formatBytes(Number(rateUp || 0))}/s ↑ / ${formatBytes(Number(rateDown || 0))}/s ↓`;
}

export function realtimeTotalLabel(rateTotal: unknown, status: string | undefined, text: (value: string) => string) {
  if (!status || status === 'ok') return `${formatBytes(Number(rateTotal || 0))}/s`;
  return trafficStatusLabel(status, text);
}

export function trafficHint(sampledAt: string | undefined, windowSeconds: number | undefined, source: string | undefined, status: string | undefined, message: string | undefined, text: (value: string) => string) {
  const parts = [];
  if (sampledAt) parts.push(`${text('采样时间')}: ${sampledAt}`);
  if (windowSeconds) parts.push(`${text('采样窗口')}: ${Number(windowSeconds).toFixed(1)}s`);
  if (source) parts.push(`${text('统计源')}: ${trafficSourceLabel(source, text)}`);
  if (status) parts.push(`${text('状态')}: ${trafficStatusLabel(status, text)}`);
  if (message) parts.push(`${text('说明')}: ${message}`);
  return parts.join(' · ') || undefined;
}

function trafficSourceLabel(source: string | undefined, text: (value: string) => string) {
  if (source === 'inbound') return text('入站原生统计');
  if (source === 'client') return text('客户端原生统计');
  if (source === 'client_aggregate') return text('客户端汇总回退');
  if (source === 'mixed') return text('混合来源');
  return source || text('MiGate');
}

function refreshOverview(queries: Array<{ refetch: () => unknown }>) {
  refreshQueries(queries);
}

export function PageTitle({ title, description, action }: { title: string; description?: string; action?: React.ReactNode }) {
  return (
    <div className="page-title">
      <div>
        <h1>{title}</h1>
        {description ? <p>{description}</p> : null}
      </div>
      {action ? <div className="page-title-actions">{action}</div> : null}
    </div>
  );
}

type MetricTone = 'teal' | 'blue' | 'emerald' | 'violet' | 'amber' | 'rose' | 'slate';

function Metric({ icon: Icon, tone, label, value, sub, title }: { icon: React.ElementType; tone: MetricTone; label: string; value: string; sub?: string; title?: string }) {
  return (
    <Card className={`metric-card metric-${tone}`} title={title}>
      <div className="metric-icon">
        <Icon className="h-5 w-5" />
      </div>
      <div className="min-w-0">
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        {sub ? <div className="metric-sub">{sub}</div> : null}
      </div>
    </Card>
  );
}

function Resource({ icon: Icon, tone, label, value }: { icon: React.ElementType; tone: MetricTone; label: string; value: string }) {
  return (
    <div className={`resource-meter metric-${tone}`}>
      <span className="resource-label">
        <span className="resource-icon">
          <Icon className="h-4 w-4" />
        </span>
        {label}
      </span>
      <span className="resource-value">{value}</span>
    </div>
  );
}
