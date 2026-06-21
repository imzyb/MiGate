import { useQueries, useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, ArrowDown, ArrowUp, Cpu, Database, HardDrive, Network, RefreshCw, Shield, Users } from 'lucide-react';
import { useMemo } from 'react';
import { getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import type { DashboardSummary, TrafficSeriesPoint } from '../api/types';
import { Card, LoadingBlock } from '../components/ui';
import { formatBytes, formatDuration, formatPercent, serviceLabel, versionLabel } from '../lib/format';
import { useI18n } from '../lib/i18n';
import { refreshQueries } from '../lib/queryInvalidation';
import { usePageVisible } from '../lib/visibility';

export default function OverviewPage() {
  const visible = usePageVisible();
  const { text } = useI18n();
  const summary = useQuery({ queryKey: ['dashboard-summary'], queryFn: api.dashboardSummary, refetchInterval: visible ? 15000 : false, retry: false, staleTime: 10_000 });
  const trafficSummary = useQuery({ queryKey: ['traffic-summary'], queryFn: api.trafficSummary, refetchInterval: visible ? 15000 : false, retry: false, staleTime: 10_000 });
  const trafficSeriesQuery = useQuery({ queryKey: ['traffic-series', 'client'], queryFn: () => api.trafficSeries({ scope_type: 'client' }), refetchInterval: visible ? 30000 : false, retry: false, staleTime: 20_000 });
  const resources = useQuery({ queryKey: ['resources'], queryFn: api.resources, refetchInterval: visible ? 10000 : false, staleTime: 5_000 });
  const [xray, singbox] = useQueries({
    queries: [
      { queryKey: ['xray-status'], queryFn: api.xrayStatus, refetchInterval: visible ? 15000 : false, staleTime: 10_000 },
      { queryKey: ['singbox-status'], queryFn: api.singboxStatus, refetchInterval: visible ? 15000 : false, staleTime: 10_000 },
    ],
  });

  const data = summary.data;
  const counts = data?.counts || emptyCounts;
  const traffic = trafficSummary.data || emptyTraffic;
  const trafficStatus = traffic.status;
  const protocols = Object.entries(data?.protocols || {}).map(([name, value]) => ({ name, value }));
  const trafficSeries = trafficSeriesQuery.data?.series || [];
  const trafficLoading = trafficSummary.isLoading && !trafficSummary.data;
  const trafficUnavailable = trafficSummary.isError && !trafficSummary.data;
  const trafficHidden = trafficLoading || trafficUnavailable;
  const trafficPlaceholder = trafficLoading ? text('加载中') : text('不可用');
  const trafficPlaceholderSub = trafficLoading ? text('等待流量摘要') : text('查看告警');
  const trafficSeriesLoading = trafficSeriesQuery.isLoading && !trafficSeriesQuery.data;

  if (summary.isLoading) return <LoadingBlock />;

  return (
    <div className="page-stack">
      <PageTitle
        title={text('运行概览')}
        description={text('VPS 面板、核心服务和业务累计用量的摘要。')}
        action={<button className="btn secondary" onClick={() => refreshOverview([summary, trafficSummary, trafficSeriesQuery, resources, xray, singbox])}><RefreshCw className="h-4 w-4" /> {text('刷新')}</button>}
      />
      <OverviewAlerts
        errors={[
          summary.error ? `${text('概览摘要加载失败')}：${errorText(summary.error)}` : '',
          trafficSummary.error ? `${text('流量摘要加载失败')}：${errorText(trafficSummary.error)}` : '',
          trafficSeriesQuery.error ? `${text('流量趋势加载失败')}：${errorText(trafficSeriesQuery.error)}` : '',
          resources.error ? `${text('资源加载失败')}：${errorText(resources.error)}` : '',
          xray.error ? `Xray ${text('状态加载失败')}：${errorText(xray.error)}` : '',
          singbox.error ? `sing-box ${text('状态加载失败')}：${errorText(singbox.error)}` : '',
          data?.validation.xray && !data.validation.xray.valid ? `Xray ${text('生成校验失败')}：${data.validation.xray.error || text('未知错误')}` : '',
          data?.validation.singbox && !data.validation.singbox.valid ? `sing-box ${text('生成校验失败')}：${data.validation.singbox.error || text('未知错误')}` : '',
        ].filter(Boolean)}
      />
      <div className="metric-grid">
        <Metric icon={Network} tone="teal" label={text('总流量')} value={trafficHidden ? trafficPlaceholder : formatBytes(traffic.total)} sub={trafficHidden ? trafficPlaceholderSub : `${formatBytes(traffic.total_up)} ↑ / ${formatBytes(traffic.total_down)} ↓`} />
        <Metric icon={Users} tone="blue" label={text('客户端')} value={String(counts.clients)} sub={`${counts.clients_active} ${text('活跃')} · ${counts.clients_expired} ${text('过期')} · ${counts.clients_limited} ${text('受限')}`} />
        <Metric icon={Shield} tone="emerald" label={text('入站')} value={String(counts.inbounds)} sub={`${counts.inbounds_enabled} ${text('已启用')}`} />
        <Metric
          icon={Activity}
          tone={trafficLoading ? 'slate' : trafficUnavailable ? 'rose' : trafficStatusTone(trafficStatus?.overall)}
          label={text('当前速率')}
          value={trafficHidden ? trafficPlaceholder : `${formatBytes(traffic.rate_total)}/s`}
          sub={trafficHidden ? trafficPlaceholderSub : trafficRateSummary(traffic.rate_up, traffic.rate_down, trafficStatus?.overall, trafficStatus?.engines, text)}
        />
        <Metric icon={Network} tone="amber" label={text('出站')} value={String(counts.outbounds)} sub={`${counts.outbounds_enabled} ${text('已启用')}`} />
        <Metric icon={Activity} tone="slate" label={text('路由规则')} value={String(counts.routing_rules)} sub={`${counts.routing_enabled} ${text('已启用')}`} />
        <Metric icon={Activity} tone={xray.data?.status === 'running' ? 'emerald' : 'rose'} label="Xray" value={text(serviceLabel(xray.data?.status))} sub={text(versionLabel(xray.data?.version))} />
        <Metric icon={Activity} tone={singbox.data?.status === 'running' ? 'emerald' : 'rose'} label="sing-box" value={text(serviceLabel(singbox.data?.status))} sub={text(versionLabel(singbox.data?.version))} />
      </div>
      <Card className="p-5">
        <h2 className="section-title mb-4">{text('最近生成状态')}</h2>
        <div className="grid gap-3 md:grid-cols-2">
          <ValidationSummary label="Xray" loading={summary.isLoading} valid={data?.validation.xray.valid} error={summary.error} detail={validationSummary(data?.validation.xray, text, summary.error)} />
          <ValidationSummary label="sing-box" loading={summary.isLoading} valid={data?.validation.singbox.valid} error={summary.error} detail={validationSummary(data?.validation.singbox, text, summary.error)} />
        </div>
      </Card>
      <div className="grid gap-4 xl:grid-cols-[1.4fr_.9fr]">
        <Card className="p-5">
          <div className="mb-4 flex items-center justify-between gap-4">
            <h2 className="section-title">{text('累计流量趋势')}</h2>
            <div className="flex gap-2 text-xs text-panel-muted">
              <span className="inline-flex items-center gap-1">
                <ArrowUp className="h-3 w-3" /> {trafficHidden ? trafficPlaceholder : formatBytes(traffic.total_up)}
              </span>
              <span className="inline-flex items-center gap-1">
                <ArrowDown className="h-3 w-3" /> {trafficHidden ? trafficPlaceholder : formatBytes(traffic.total_down)}
              </span>
            </div>
          </div>
          <div className="h-64">
            <TrafficChart data={trafficSeries} loading={trafficSeriesLoading} />
          </div>
        </Card>
        <Card className="p-5">
          <h2 className="section-title mb-4">{text('服务器资源')}</h2>
          <div className="grid gap-3">
            <Resource icon={Cpu} tone="blue" label="CPU" value={formatPercent(resources.data?.cpu_percent)} />
            <Resource icon={Database} tone="violet" label={text('内存')} value={`${formatBytes(resources.data?.memory_used)} / ${formatBytes(resources.data?.memory_total)}`} />
            <Resource icon={HardDrive} tone="amber" label={text('磁盘')} value={`${formatBytes(resources.data?.disk_used)} / ${formatBytes(resources.data?.disk_total)}`} />
            <Resource icon={Activity} tone="teal" label={text('运行时间')} value={formatDuration(resources.data?.uptime_seconds)} />
          </div>
        </Card>
      </div>
      <Card className="p-5">
        <h2 className="section-title mb-4">{text('协议分布')}</h2>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {protocols.length ? protocols.map((item) => <div key={item.name} className="rounded-lg bg-panel-soft p-3 text-sm"><b>{item.name}</b><span className="ml-2 text-panel-muted">{item.value}</span></div>) : <span className="text-sm text-panel-muted">{text('暂无入站')}</span>}
        </div>
      </Card>
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

const emptyTraffic = {
  total_up: 0,
  total_down: 0,
  total: 0,
  rate_up: 0,
  rate_down: 0,
  rate_total: 0,
  status: { overall: 'waiting', engines: { xray: 'not_configured', singbox: 'not_configured' } },
  generated_at: '',
};

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

function TrafficChart({ data, loading }: { data: TrafficSeriesPoint[]; loading?: boolean }) {
  const { text } = useI18n();
  const chart = useMemo(() => buildChart(data), [data]);
  if (loading) {
    return <div className="flex h-full items-center justify-center text-sm text-panel-muted">{text('流量趋势加载中')}</div>;
  }
  if (data.length === 0) {
    return <div className="flex h-full items-center justify-center text-sm text-panel-muted">{text('暂无流量数据')}</div>;
  }
  return (
    <div className="relative h-full w-full">
      <svg className="h-full w-full overflow-visible" viewBox="0 0 640 220" role="img" aria-label={text('累计流量趋势')}>
        <defs>
          <linearGradient id="traffic-up-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#0f766e" stopOpacity="0.32" />
            <stop offset="100%" stopColor="#0f766e" stopOpacity="0.04" />
          </linearGradient>
          <linearGradient id="traffic-down-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#b45309" stopOpacity="0.26" />
            <stop offset="100%" stopColor="#b45309" stopOpacity="0.04" />
          </linearGradient>
        </defs>
        <g stroke="#e5e7eb" strokeWidth="1">
          {[0, 1, 2, 3].map((line) => <line key={line} x1="0" x2="640" y1={line * 55} y2={line * 55} />)}
        </g>
        <path d={chart.upArea} fill="url(#traffic-up-fill)" />
        <path d={chart.downArea} fill="url(#traffic-down-fill)" />
        <path d={chart.upLine} fill="none" stroke="#0f766e" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" />
        <path d={chart.downLine} fill="none" stroke="#b45309" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" />
        {chart.points.map((point) => (
          <g key={point.name + point.x}>
            <circle cx={point.x} cy={point.upY} fill="#0f766e" r="3.5" />
            <circle cx={point.x} cy={point.downY} fill="#b45309" r="3.5" />
            <title>{`${formatSeriesTime(point.time)} · ${text('累计')} ↑ ${formatBytes(point.up)} / ↓ ${formatBytes(point.down)}`}</title>
          </g>
        ))}
      </svg>
    </div>
  );
}

function buildChart(data: TrafficSeriesPoint[]) {
  const width = 640;
  const bottom = 205;
  if (data.length === 0) {
    return { points: [], upLine: '', downLine: '', upArea: '', downArea: '' };
  }
  const max = Math.max(1, ...data.flatMap((item) => [Number(item.up || 0), Number(item.down || 0)]));
  const xFor = (index: number) => data.length === 1 ? width / 2 : (index / (data.length - 1)) * width;
  const yFor = (value: number) => bottom - (Number(value || 0) / max) * 180;
  const points = data.map((item, index) => ({
    name: item.name,
    time: item.time || item.name,
    up: Number(item.up || 0),
    down: Number(item.down || 0),
    x: xFor(index),
    upY: yFor(item.up),
    downY: yFor(item.down),
  }));
  const line = (key: 'upY' | 'downY') => points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x.toFixed(1)} ${point[key].toFixed(1)}`).join(' ');
  const area = (path: string) => `${path} L ${points[points.length - 1].x.toFixed(1)} ${bottom} L ${points[0].x.toFixed(1)} ${bottom} Z`;
  const upLine = line('upY');
  const downLine = line('downY');
  return { points, upLine, downLine, upArea: area(upLine), downArea: area(downLine) };
}

function formatSeriesTime(value: string | undefined) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
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
  if (status === 'partial') return text('部分不可用');
  if (status === 'unsupported') return text('当前 sing-box 二进制不支持实时统计');
  if (status === 'not_configured') return text('未配置对应核心入站');
  if (status === 'unavailable') return text('统计接口不可用');
  if (status === 'stale') return text('统计状态过期');
  if (status === 'cumulative_only') return text('仅显示累计');
  return text('等待采样');
}

function trafficStatusTone(status: string | undefined): MetricTone {
  if (status === 'ok') return 'emerald';
  if (status === 'partial' || status === 'unsupported') return 'amber';
  if (status === 'unavailable' || status === 'stale') return 'rose';
  return 'slate';
}

export function engineStatusSummary(engines: Record<string, string> | undefined, text: (value: string) => string) {
  if (!engines) return text('等待采样');
  return Object.entries(engines).map(([engine, status]) => `${engine}: ${trafficStatusLabel(status, text)}`).join(' · ');
}

export function trafficRateSummary(rateUp: number, rateDown: number, status: string | undefined, engines: Record<string, string> | undefined, text: (value: string) => string) {
  const rate = `${formatBytes(rateUp)}/s ↑ / ${formatBytes(rateDown)}/s ↓`;
  const statusLabel = trafficStatusLabel(status, text);
  if (!status || status === 'ok') {
    return `${rate} · ${statusLabel}`;
  }
  return `${rate} · ${statusLabel} · ${engineStatusSummary(engines, text)}`;
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
      {action}
    </div>
  );
}

type MetricTone = 'teal' | 'blue' | 'emerald' | 'violet' | 'amber' | 'rose' | 'slate';

function Metric({ icon: Icon, tone, label, value, sub }: { icon: React.ElementType; tone: MetricTone; label: string; value: string; sub?: string }) {
  return (
    <Card className={`metric-card metric-${tone}`}>
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
