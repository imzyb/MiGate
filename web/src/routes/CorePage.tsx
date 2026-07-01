import { useMutation, useQuery } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, ChevronDown, Download, FileText, Play, RefreshCw, RotateCcw, ShieldCheck, Square, Trash2, XCircle } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import type { CoreActionResponse, CoreConfigPreview, CoreDiagnosticAction, CoreDiagnostics, CoreStatus } from '../api/types';
import { Card, LoadingBlock, SpinnerButton, useConfirm, useToast } from '../components/ui';
import { formatBytes, serviceLabel, versionLabel } from '../lib/format';
import { useI18n } from '../lib/i18n';
import { refreshQueries, refreshQuery } from '../lib/queryInvalidation';
import { usePageVisible } from '../lib/visibility';
import { PageTitle } from './OverviewPage';

export default function CorePage({ core }: { core: 'xray' | 'singbox' }) {
  const visible = usePageVisible();
  const { showToast } = useToast();
  const { text } = useI18n();
  const confirm = useConfirm();
  const label = core === 'xray' ? 'Xray' : 'sing-box';
  const endpoints = core === 'xray'
    ? { status: api.xrayStatus, version: api.xrayVersion, config: api.xrayConfig, configPreview: api.xrayConfigPreview, diagnostics: api.xrayDiagnostics, logs: api.xrayLogs, validate: api.xrayValidate, apply: api.xrayApply, install: api.xrayInstall, uninstall: api.xrayUninstall, delete: api.xrayDelete, restart: api.xrayRestart, stop: api.xrayStop }
    : { status: api.singboxStatus, version: api.singboxVersion, config: api.singboxConfig, configPreview: api.singboxConfigPreview, diagnostics: api.singboxDiagnostics, logs: api.singboxLogs, validate: api.singboxValidate, apply: api.singboxApply, install: api.singboxInstall, uninstall: api.singboxUninstall, delete: api.singboxDelete, restart: api.singboxRestart, stop: api.singboxStop };
  const [lastResult, setLastResult] = useState<{ ok: boolean; message: string; detail?: string } | null>(null);
  const [applyPollingUntil, setApplyPollingUntil] = useState<number>(0);
  const [showAdvancedMaintenance, setShowAdvancedMaintenance] = useState(false);
  const [showRawDiagnostics, setShowRawDiagnostics] = useState(false);
  const statusQuery = useQuery({ queryKey: [core, 'status'], queryFn: endpoints.status, refetchInterval: (query) => {
    const current = query.state.data as CoreStatus | undefined;
    const applyRunning = coreApplyJobInProgress(current?.apply_job?.status) || Date.now() < applyPollingUntil;
    if (!visible) return false;
    return applyRunning ? 1500 : coreStatusRefetchInterval(true);
  }, staleTime: 10_000 });
  const versionQuery = useQuery({ queryKey: [core, 'version'], queryFn: endpoints.version, retry: false, staleTime: 10 * 60_000 });
  const configQuery = useQuery({ queryKey: [core, 'config'], queryFn: endpoints.config, staleTime: 60_000 });
  const configPreviewQuery = useQuery({ queryKey: [core, 'config-preview'], queryFn: endpoints.configPreview, staleTime: 60_000 });
  const diagnosticsQuery = useQuery({ queryKey: [core, 'diagnostics'], queryFn: endpoints.diagnostics, staleTime: 20_000 });
  const logsQuery = useQuery({ queryKey: [core, 'logs'], queryFn: endpoints.logs, enabled: false });
  const validate = useMutation({
    mutationFn: endpoints.validate,
    onSuccess: (data) => {
      const message = data.valid ? `${label} 生成校验通过` : (data.error || `${label} 生成校验失败`);
      setLastResult({ ok: data.valid, message, detail: validationDetail(data) });
      showToast(text(message), data.valid ? 'success' : 'error');
    },
    onError: (error) => {
      const message = errorMessage(error, `${label} 生成校验失败`);
      setLastResult({ ok: false, message });
      showToast(message, 'error');
    },
  });
  const apply = useMutation({
    mutationFn: endpoints.apply,
    onSuccess: (data) => {
      const result = coreActionResult(data, `${label} 配置已应用`);
      setLastResult({ ok: result.ok, message: result.message, detail: result.detail });
      showToast(text(result.message), result.tone || (result.ok ? 'success' : 'error'));
      if (data.accepted || coreApplyJobInProgress(data.apply_job?.status)) {
        setApplyPollingUntil(Date.now() + 30_000);
      }
      refreshQuery(statusQuery);
      refreshQuery(diagnosticsQuery);
      if (result.ok) {
        refreshQueries([configQuery, configPreviewQuery]);
      }
    },
    onError: (error) => setActionError(error, `${label} 应用失败`, setLastResult, showToast),
  });
  const install = useMutation({
    mutationFn: endpoints.install,
    onSuccess: (data) => {
      const result = coreActionResult(data, `${label} 安装命令已执行`);
      setLastResult({ ok: result.ok, message: result.message, detail: result.detail });
      showToast(text(result.message), result.ok ? 'success' : 'error');
      refreshQueries([statusQuery, versionQuery, diagnosticsQuery]);
    },
    onError: (error) => setActionError(error, `${label} 安装失败`, setLastResult, showToast),
  });
  const uninstall = useMutation({
    mutationFn: endpoints.uninstall,
    onSuccess: (data) => {
      const result = coreActionResult(data, `${label} 取消托管命令已执行`);
      setLastResult({ ok: result.ok, message: result.message, detail: result.detail });
      showToast(text(result.message), result.ok ? 'success' : 'error');
      refreshQueries([statusQuery, versionQuery, diagnosticsQuery]);
    },
    onError: (error) => setActionError(error, `${label} 取消托管失败`, setLastResult, showToast),
  });
  const deleteCore = useMutation({
    mutationFn: endpoints.delete,
    onSuccess: (data) => {
      const result = coreActionResult(data, `${label} 删除命令已执行`);
      setLastResult({ ok: result.ok, message: result.message, detail: result.detail });
      showToast(text(result.message), result.ok ? 'success' : 'error');
      refreshQueries([statusQuery, versionQuery, diagnosticsQuery]);
    },
    onError: (error) => setActionError(error, `${label} 删除失败`, setLastResult, showToast),
  });
  const restart = useMutation({
    mutationFn: endpoints.restart,
    onSuccess: (data) => {
      const result = coreActionResult(data, `${label} 已重启`);
      setLastResult({ ok: result.ok, message: result.message, detail: result.detail });
      showToast(text(result.message), result.ok ? 'success' : 'error');
      refreshQueries([statusQuery, versionQuery, diagnosticsQuery]);
    },
    onError: (error) => setActionError(error, `${label} 重启失败`, setLastResult, showToast),
  });
  const stop = useMutation({
    mutationFn: endpoints.stop,
    onSuccess: (data) => {
      const result = coreActionResult(data, `${label} 已停止`);
      setLastResult({ ok: result.ok, message: result.message, detail: result.detail });
      showToast(text(result.message), result.ok ? 'success' : 'error');
      refreshQueries([statusQuery, versionQuery, diagnosticsQuery]);
    },
    onError: (error) => setActionError(error, `${label} 停止失败`, setLastResult, showToast),
  });
  if (statusQuery.isLoading) return <LoadingBlock />;
  const status = statusQuery.data;
  const diagnostics = diagnosticsQuery.data;
  const installed = coreInstalledWithDiagnostics(status, diagnostics);
  const installActionLabel = installed ? '升级/重装核心' : '安装核心';
  const configPreview = configPreviewQuery.data;
  const health = coreHealthSummary(status, diagnostics, configPreview, diagnosticsQuery.isLoading, diagnosticsQuery.error, configPreviewQuery.isLoading, configPreviewQuery.error);
  const userSync = coreUserSyncState(status, diagnostics, configPreview, configPreviewQuery.isLoading, configPreviewQuery.error);
  const applyButtonLabel = coreApplyButtonLabel(userSync);
  return (
    <div className={`page-stack core-page core-page-${core}`}>
      <PageTitle
        title={text(`${label} 核心管理`)}
        description={text('集中处理运行状态、配置同步、端口监听和核心维护。')}
      />
      <div className="core-switch-tabs" aria-label={text('核心切换')}>
        <a href="/core/xray" className={`core-switch-tab${core === 'xray' ? ' core-switch-tab-active' : ''}`}>Xray</a>
        <a href="/core/singbox" className={`core-switch-tab${core === 'singbox' ? ' core-switch-tab-active' : ''}`}>sing-box</a>
      </div>
      <CoreOverview label={label} status={status} diagnostics={diagnostics} preview={configPreview} fallbackVersion={versionQuery.data?.version} health={health} text={text} />
      <Card className="core-card core-operations-card p-5">
        <div className="core-card-header mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 className="section-title">{text('主操作')}</h2>
            <p className="mt-1 text-sm text-panel-muted">{text(health.nextAction)}</p>
          </div>
          <StatusPill tone={health.tone} label={text(health.label)} />
        </div>
        <div className="core-action-groups">
          <div className="core-action-group">
            <div className="core-action-group-title">{text('常用')}</div>
            <div className="core-action-row">
              <button className="btn secondary" onClick={() => refreshQueries([statusQuery, versionQuery, diagnosticsQuery, configPreviewQuery])}><RefreshCw className="h-4 w-4" /> {text('刷新')}</button>
              <SpinnerButton className="btn secondary" loading={validate.isPending} onClick={() => validate.mutate()}><ShieldCheck className="h-4 w-4" /> {text('生成校验')}</SpinnerButton>
              <SpinnerButton className="btn primary" loading={apply.isPending} onClick={async () => (await confirm({ title: text(`${applyButtonLabel} ${label} 配置？`), description: text('该操作会重新生成并应用核心配置。') })) && apply.mutate()}><Play className="h-4 w-4" /> {text(applyButtonLabel)}</SpinnerButton>
            </div>
          </div>
          <div className="core-action-group">
            <div className="core-action-group-title">{text('维护')}</div>
            <div className="core-action-row">
              <SpinnerButton className="btn secondary" loading={restart.isPending} disabled={!installed} title={text(installed ? '重启核心' : '核心未安装')} onClick={async () => installed && (await confirm({ title: text(`重启 ${label} 核心？`), description: text('该操作会通过 systemd 重启核心服务。') })) && restart.mutate()}><RotateCcw className="h-4 w-4" /> {text('重启核心')}</SpinnerButton>
              <button className="btn secondary" onClick={() => setShowAdvancedMaintenance((value) => !value)}>{text('高级维护')}</button>
            </div>
          </div>
          {showAdvancedMaintenance ? (
            <div className="core-action-group core-action-group-danger">
              <div className="core-action-group-title">{text('危险')}</div>
              <div className="core-action-row">
                <SpinnerButton className="btn secondary" loading={install.isPending} onClick={async () => (await confirm({ title: text(`${installActionLabel} ${label}？`), description: text(installed ? '该操作会重新执行安装脚本，通常用于升级或修复当前核心。' : '该操作会执行系统安装命令。') })) && install.mutate()}><Download className="h-4 w-4" /> {text(installActionLabel)}</SpinnerButton>
                <SpinnerButton className="btn danger ghost-danger" loading={stop.isPending} disabled={!installed} title={text(installed ? '停止核心' : '核心未安装')} onClick={async () => installed && (await confirm({ title: text(`停止 ${label} 核心？`), description: text('该操作会停止核心服务，入站连接会中断。'), tone: 'danger' })) && stop.mutate()}><Square className="h-4 w-4" /> {text('停止核心')}</SpinnerButton>
                <SpinnerButton className="btn danger ghost-danger" loading={uninstall.isPending} disabled={!installed} title={text(installed ? '取消托管核心' : '核心未安装')} onClick={async () => installed && (await confirm({ title: text(`取消托管 ${label} 核心？`), description: text('该操作会停止并移除 MiGate 管理的 systemd 服务，保留核心二进制和配置。'), tone: 'danger' })) && uninstall.mutate()}><Trash2 className="h-4 w-4" /> {text('取消托管核心')}</SpinnerButton>
                <SpinnerButton className="btn danger ghost-danger" loading={deleteCore.isPending} disabled={!installed} title={text(installed ? '删除核心' : '核心未安装')} onClick={async () => installed && (await confirm({ title: text(`删除 ${label} 核心？`), description: text('该操作会停止服务并删除核心二进制，保留标准配置文件。'), tone: 'danger' })) && deleteCore.mutate()}><Trash2 className="h-4 w-4" /> {text('删除核心')}</SpinnerButton>
              </div>
            </div>
          ) : null}
        </div>
      </Card>
      {lastResult ? (
        <Card className={`core-card core-result-card p-4 ${lastResult.ok ? 'border-emerald-200 bg-emerald-50' : 'border-red-200 bg-red-50'}`}>
          <div className={`flex items-start gap-3 text-sm ${lastResult.ok ? 'text-emerald-800' : 'text-red-700'}`}>
            {lastResult.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4" /> : <XCircle className="mt-0.5 h-4 w-4" />}
            <div className="min-w-0">
              <div className="font-medium">{text(lastResult.message)}</div>
              {lastResult.detail ? <pre className="mt-2 whitespace-pre-wrap break-words text-xs leading-5">{lastResult.detail}</pre> : null}
            </div>
          </div>
        </Card>
      ) : null}
      <CoreConfigSync preview={configPreview} loading={configPreviewQuery.isLoading} error={configPreviewQuery.error} onRefresh={() => refreshQueries([configQuery, configPreviewQuery])} text={text} />
      <CorePortDiagnostics status={status} diagnostics={diagnostics} text={text} />
      <button className="btn secondary" onClick={() => setShowRawDiagnostics((value) => !value)}>{text('高级详情')}</button>
      {showRawDiagnostics ? (
        <>
          {status?.commands_executed?.length ? (
            <Card className="core-card p-5">
              <h2 className="section-title mb-3">{text('最近命令')}</h2>
              <pre className="code-block core-code-block">{status.commands_executed.join('\n')}</pre>
            </Card>
          ) : null}
          <CoreDiagnosticsPanel diagnostics={diagnostics} loading={diagnosticsQuery.isLoading} error={diagnosticsQuery.error} onRefresh={() => refreshQuery(diagnosticsQuery)} text={text} />
          <CoreDisclosure title={text('配置预览')} icon={<FileText className="h-4 w-4" />} action={<button className="btn secondary h-8" onClick={() => refreshQueries([configQuery, configPreviewQuery])}>{text('刷新配置')}</button>}>
            <pre className="code-block core-code-block">{JSON.stringify(configQuery.data || {}, null, 2)}</pre>
          </CoreDisclosure>
          <CoreDisclosure title={text('最近日志')} icon={<FileText className="h-4 w-4" />} action={<button className="btn secondary h-8" onClick={() => refreshQuery(logsQuery)}>{text('加载日志')}</button>}>
            <pre className="code-block core-code-block">{formatLogs(logsQuery.data, text('点击“加载日志”查看最近日志。'))}</pre>
          </CoreDisclosure>
        </>
      ) : null}
    </div>
  );
}

function CoreOverview({ label, status, diagnostics, preview, fallbackVersion, health, text }: { label: string; status?: CoreStatus; diagnostics?: CoreDiagnostics; preview?: CoreConfigPreview; fallbackVersion?: string; health: CoreHealthSummary; text: (value: string) => string }) {
  const installed = coreInstalledWithDiagnostics(status, diagnostics);
  const ports = coreListeningDiagnostics(status, diagnostics);
  const listeningCount = ports.filter((port) => port.listening).length;
  const missingCount = ports.filter((port) => !port.listening).length;
  const managed = status?.managed ?? diagnostics?.managed;
  const serviceStatus = status?.status || diagnostics?.service_status;
  const configPath = status?.config_path || diagnostics?.config_path || preview?.config_path || '-';
  const userSync = coreUserSyncState(status, diagnostics, preview);
  const applyJob = status?.apply_job;
  const stats = [
    { label: '安装', value: installed ? '已安装' : '未安装', tone: installed ? 'ok' : 'error' },
    { label: '托管', value: managed ? '已托管' : '未托管', tone: managed ? 'ok' : 'warning' },
    { label: '运行', value: serviceLabel(serviceStatus), tone: serviceStatus === 'running' ? 'ok' : 'error' },
    { label: '配置', value: userSync.label, tone: userSync.tone },
  ] satisfies Array<{ label: string; value: string; tone: StatusTone }>;
  return (
    <Card className={`core-overview core-overview-${health.tone} p-5`}>
      <div className="core-overview-main">
        <div className="core-overview-status">
          {health.tone === 'ok' ? <CheckCircle2 className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
          <div className="min-w-0">
            <div className="core-overview-label">{text(label)}</div>
            <h2>{text(health.headline)}</h2>
            <p>{text(health.detail)}</p>
          </div>
        </div>
        <div className="core-overview-meta">
          <div>
            <span>{text('版本')}</span>
            <strong title={versionLabel(status?.version || fallbackVersion)}>{versionLabel(status?.version || fallbackVersion)}</strong>
          </div>
          <div>
            <span>{text('连接')}</span>
            <strong>{status?.active_connections || 0}</strong>
          </div>
          <div>
            <span>{text('监听')}</span>
            <strong>{ports.length ? `${listeningCount}/${ports.length}` : '-'}</strong>
          </div>
          <div>
            <span>{text('内存')}</span>
            <strong>{formatBytes(status?.memory_rss_bytes)}</strong>
          </div>
        </div>
      </div>
      <div className="core-overview-strip">
        {stats.map((item) => <StatusPill key={item.label} tone={item.tone} label={`${text(item.label)}：${text(item.value)}`} />)}
        {missingCount ? <StatusPill tone="warning" label={text(`未监听 ${missingCount} 个端口`)} /> : null}
        {applyJob && coreApplyJobInProgress(applyJob.status) ? <StatusPill tone="warning" label={text(`应用进行中：${applyJobStatusLabel(applyJob.status)}`)} /> : null}
      </div>
      <div className="core-overview-path">
        <span>{text('配置路径')}</span>
        <code>{configPath}</code>
      </div>
      <div className="mt-4 rounded-lg border border-panel-line bg-panel-soft p-3 text-sm">
        <div className="font-medium text-panel-text">{text(userSync.action)}</div>
        <div className="mt-1 text-panel-muted">{text(userSync.detail)}</div>
      </div>
      <details className="core-details mt-3">
        <summary><span>{text('高级详情')}</span><ChevronDown className="h-4 w-4" /></summary>
        <div className="core-details-body grid gap-2 text-sm text-panel-muted">
          {status?.pending_reason ? <div>{text(`待应用原因：${status.pending_reason}`)}</div> : null}
          {status?.pending_updated_at ? <div>{text(`待应用时间：${status.pending_updated_at}`)}</div> : null}
          {status?.pending_apply_error ? <div>{text(`待应用错误：${status.pending_apply_error}`)}{status.pending_apply_detail ? ` · ${text(status.pending_apply_detail)}` : ''}</div> : null}
          {status?.generated_hash ? <div>generated_hash: <code>{status.generated_hash}</code></div> : null}
          {status?.applied_config_hash ? <div>applied_hash: <code>{status.applied_config_hash}</code></div> : null}
          {preview?.disk?.hash ? <div>disk_hash: <code>{preview.disk.hash}</code></div> : null}
          {applyJob ? <div>{text(`应用任务：${applyJobStatusLabel(applyJob.status)}`)}{applyJob.retry_count ? ` · retry ${applyJob.retry_count}/${applyJob.max_retries || 0}` : ''}{applyJob.message ? ` · ${text(applyJob.message)}` : ''}{applyJob.error ? ` · ${text(applyJob.error)}` : ''}{applyJob.detail ? ` · ${text(applyJob.detail)}` : ''}</div> : null}
        </div>
      </details>
    </Card>
  );
}

function CorePortDiagnostics({ status, diagnostics, text }: { status?: CoreStatus; diagnostics?: CoreDiagnostics; text: (value: string) => string }) {
  const ports = coreListeningDiagnostics(status, diagnostics);
  const missing = ports.some((port) => !port.listening);
  return (
    <Card className={`core-card core-port-card p-5 ${missing ? 'border-amber-200 bg-amber-50' : ''}`}>
      <div className="core-card-header mb-3 flex items-center justify-between gap-3">
        <div>
          <h2 className="section-title">{text('监听端口')}</h2>
          <p className="mt-1 text-sm text-panel-muted">{text(corePortSummary(ports))}</p>
        </div>
        <StatusPill tone={missing ? 'warning' : ports.length ? 'ok' : 'neutral'} label={text(missing ? '存在未监听端口' : ports.length ? '监听正常' : '暂无端口')} />
      </div>
      {!ports.length ? <div className="core-empty-state">{text('当前没有可展示的监听端口。')}</div> : null}
      {ports.length ? (
        <div className="overflow-x-auto">
          <table className="core-port-table w-full text-left text-sm">
            <thead className="text-xs text-panel-muted">
              <tr>
                <th className="py-2 pr-3">{text('入站 ID')}</th>
                <th className="py-2 pr-3">{text('协议')}</th>
                <th className="py-2 pr-3">{text('端口')}</th>
                <th className="py-2 pr-3">UDP/TCP</th>
                <th className="py-2 pr-3">{text('传输')}</th>
                <th className="py-2 pr-3">{text('安全')}</th>
                <th className="py-2 pr-3">{text('详情')}</th>
                <th className="py-2 pr-3">{text('监听')}</th>
              </tr>
            </thead>
            <tbody>
              {ports.map((port) => (
                <tr key={`${port.inboundId}-${port.port}-${port.transport}`} className={!port.listening ? 'font-medium text-amber-800' : ''}>
                  <td className="py-2 pr-3">{port.inboundId}</td>
                  <td className="py-2 pr-3">{port.protocol}</td>
                  <td className="py-2 pr-3">{port.port}</td>
                  <td className="py-2 pr-3">{port.transport.toUpperCase()}</td>
                  <td className="py-2 pr-3">{port.network || '-'}</td>
                  <td className="py-2 pr-3">{port.security || '-'}</td>
                  <td className="py-2 pr-3">{port.detail || '-'}</td>
                  <td className="py-2 pr-3"><StatusPill tone={port.listening ? 'ok' : 'warning'} label={text(port.listening ? '正在监听' : '未监听')} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </Card>
  );
}

function CoreDiagnosticsPanel({ diagnostics, loading, error, onRefresh, text }: { diagnostics?: CoreDiagnostics; loading: boolean; error?: unknown; onRefresh: () => void; text: (value: string) => string }) {
  const summary = coreDiagnosticsSummary(diagnostics, loading, error);
  const toneClass = summary.tone === 'error' ? 'border-red-200 bg-red-50' : summary.tone === 'warning' ? 'border-amber-200 bg-amber-50' : '';
  const iconClass = summary.tone === 'error' ? 'text-red-700' : summary.tone === 'warning' ? 'text-amber-700' : 'text-emerald-700';
  const checks = diagnosticChecksForPanel(diagnostics, loading, error);
  const actions = coreDiagnosticActions(diagnostics);
  const hasIssues = summary.tone !== 'ok';
  const detailsOpen = hasIssues && !loading;
  return (
    <Card className={`core-card core-diagnostics-card p-5 ${toneClass}`}>
      <div className="core-card-header mb-4 flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          {summary.tone === 'ok' ? <CheckCircle2 className={`h-5 w-5 ${iconClass}`} /> : <AlertTriangle className={`h-5 w-5 ${iconClass}`} />}
          <div className="min-w-0">
            <h2 className="section-title">{text('诊断')}</h2>
            <div className={`mt-1 text-sm font-medium ${iconClass}`}>{text(hasIssues ? issueSummary(diagnostics, summary) : '未发现需要处理的问题')}</div>
          </div>
        </div>
        <button className="btn secondary h-8" onClick={onRefresh}><RefreshCw className="h-4 w-4" /> {text('刷新诊断')}</button>
      </div>
      {hasIssues ? (
        <div className="core-issue-callout">
          <div>
            <div className="text-xs font-medium text-panel-muted">{text('推荐操作')}</div>
            <div className="mt-1 text-sm font-medium text-panel-text">{text(recommendedAction(diagnostics, summary))}</div>
          </div>
        </div>
      ) : null}
      <div className="core-check-grid">
        {checks.map((check) => (
          <div key={check.label} className="core-check-item">
            <div className="text-xs text-panel-muted">{text(check.label)}</div>
            <div className={`mt-1 text-sm font-medium ${check.ok === true ? 'text-emerald-700' : check.ok === false ? 'text-amber-800' : 'text-panel-muted'}`}>{text(check.value)}</div>
          </div>
        ))}
      </div>
      <CoreDiagnosticsDetails diagnostics={diagnostics} actions={actions} openByDefault={detailsOpen} summary={summary} text={text} />
    </Card>
  );
}

function CoreDiagnosticsDetails({ diagnostics, actions, openByDefault, summary, text }: { diagnostics?: CoreDiagnostics; actions: CoreDiagnosticAction[]; openByDefault: boolean; summary: ReturnType<typeof coreDiagnosticsSummary>; text: (value: string) => string }) {
  const [open, setOpen] = useState(openByDefault);
  useEffect(() => {
    setOpen(openByDefault);
  }, [openByDefault]);
  return (
    <details className="core-details" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary><span>{text('诊断详情')}</span><ChevronDown className="h-4 w-4" /></summary>
      <div className="core-details-body">
        {summary.detail ? <div className="mb-3 text-sm text-panel-muted">{text(diagnosticWarningLabel(summary.detail))}</div> : null}
        {diagnostics?.missing_listeners?.length ? (
          <div className="mt-4">
            <div className="mb-2 text-xs font-medium text-panel-muted">{text('未监听端口')}</div>
            <div className="flex flex-wrap gap-2">
              {diagnostics.missing_listeners.map((listener) => <span key={`${listener.inbound_id}-${listener.port}`} className="rounded border border-amber-300 bg-amber-100 px-2 py-1 text-xs font-medium text-amber-900">{listener.port}/{String(listener.transport || listener.network || 'tcp').toLowerCase()}</span>)}
            </div>
          </div>
        ) : null}
        {diagnostics?.config_error ? (
          <div className="mt-4">
            <div className="mb-2 text-xs font-medium text-panel-muted">{text('配置校验错误')}</div>
            <pre className="code-block core-code-block">{diagnostics.config_error}</pre>
          </div>
        ) : null}
        {diagnostics?.warnings?.length ? <DiagnosticList title={text('警告')} items={diagnostics.warnings.map((item) => text(diagnosticWarningLabel(item)))} /> : null}
        {actions.length ? <DiagnosticActionList title={text('建议操作')} actions={actions} text={text} /> : diagnostics?.suggestions?.length ? <DiagnosticList title={text('建议操作')} items={diagnostics.suggestions.map((item) => text(item))} /> : null}
        {diagnostics?.recent_logs?.length ? (
          <div className="mt-4">
            <div className="mb-2 text-xs font-medium text-panel-muted">{text('最近日志摘要')}</div>
            <pre className="code-block core-code-block">{diagnostics.recent_logs.slice(-8).join('\n')}</pre>
          </div>
        ) : null}
      </div>
    </details>
  );
}

function DiagnosticList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="mt-4">
      <div className="mb-2 text-xs font-medium text-panel-muted">{title}</div>
      <ul className="space-y-1 text-sm text-panel-text">
        {items.map((item) => <li key={item} className="break-words">- {item}</li>)}
      </ul>
    </div>
  );
}

function DiagnosticActionList({ title, actions, text }: { title: string; actions: CoreDiagnosticAction[]; text: (value: string) => string }) {
  return (
    <div className="mt-4">
      <div className="mb-2 text-xs font-medium text-panel-muted">{title}</div>
      <div className="grid gap-2">
        {actions.map((action) => {
          const formatted = formatDiagnosticAction(action);
          return (
            <div key={`${action.code}-${action.inbound_id || 0}-${action.port || 0}-${action.command || action.message}`} className="rounded border border-panel-border bg-white/70 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded px-2 py-0.5 text-xs font-medium ${diagnosticActionToneClass(action.severity)}`}>{text(formatted.severity)}</span>
                <span className="text-xs text-panel-muted">{text(formatted.category)}</span>
                {formatted.target ? <span className="text-xs text-panel-muted">{formatted.target}</span> : null}
              </div>
              <div className="mt-2 break-words text-panel-text">{text(formatted.message)}</div>
              {formatted.command ? <code className="mt-2 block overflow-x-auto rounded border border-panel-border bg-panel-soft px-2 py-1 text-xs text-panel-text">{formatted.command}</code> : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CoreConfigSync({ preview, loading, error, onRefresh, text }: { preview?: CoreConfigPreview; loading: boolean; error?: unknown; onRefresh: () => void; text: (value: string) => string }) {
  const state = configSyncState(preview, loading, error);
  return (
    <Card className={`core-card core-config-card p-5 ${state.ok === false ? 'border-amber-200 bg-amber-50' : ''}`}>
      <div className="core-card-header mb-3 flex items-center justify-between gap-3">
        <div>
          <h2 className="section-title">{text('配置状态')}</h2>
          <p className="mt-1 text-sm text-panel-muted">{text('对比磁盘配置与数据库生成配置。')}</p>
        </div>
        <button className="btn secondary h-8" onClick={onRefresh}>{text('刷新配置')}</button>
      </div>
      <div className="core-config-summary">
        <div>
          <span>{text('配置路径')}</span>
          <code>{preview?.config_path || preview?.disk?.config_path || preview?.generated?.config_path || '-'}</code>
        </div>
        <StatusPill tone={state.ok === false ? 'warning' : state.ok ? 'ok' : 'neutral'} label={text(state.label)} />
      </div>
      {state.detail ? <div className="mt-2 text-xs text-panel-muted">{text(state.detail)}</div> : null}
      {preview?.pending_apply ? (
        <div className="mt-3 rounded border border-amber-300 bg-amber-100 px-3 py-2 text-sm font-medium text-amber-900">
          {text('有更改尚未生效，请点击上方“应用配置”重新生成并重启核心。')}
        </div>
      ) : null}
      <details className="core-details">
        <summary><span>{text('查看配置对比')}</span><ChevronDown className="h-4 w-4" /></summary>
        <div className="core-details-body core-config-compare">
          <div>
            <div className="mb-2 text-xs font-medium text-panel-muted">{text('当前磁盘配置')}</div>
            <pre className="code-block core-code-block">{JSON.stringify(preview?.disk?.config || preview?.disk || {}, null, 2)}</pre>
          </div>
          <div>
            <div className="mb-2 text-xs font-medium text-panel-muted">{text('数据库生成配置')}</div>
            <pre className="code-block core-code-block">{JSON.stringify(preview?.generated?.config || preview?.generated || {}, null, 2)}</pre>
          </div>
        </div>
      </details>
    </Card>
  );
}

function CoreDisclosure({ title, icon, action, children }: { title: string; icon?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <Card className="core-card core-disclosure-card p-5">
      <div className="core-disclosure-header">
        <details className="core-details">
          <summary>
            <span className="core-disclosure-title">{icon}{title}</span>
            <ChevronDown className="h-4 w-4" />
          </summary>
          <div className="core-details-body">{children}</div>
        </details>
        {action ? <div className="core-disclosure-actions">{action}</div> : null}
      </div>
    </Card>
  );
}

type StatusTone = 'ok' | 'warning' | 'error' | 'neutral';

type CoreHealthSummary = {
  tone: Exclude<StatusTone, 'neutral'>;
  label: string;
  headline: string;
  detail: string;
  nextAction: string;
};

type CoreUserSyncState = {
  key: 'in_sync' | 'syncing' | 'waiting' | 'failed' | 'needs_check' | 'unknown';
  label: string;
  headline: string;
  detail: string;
  action: string;
  tone: StatusTone;
};

function StatusPill({ tone, label }: { tone: StatusTone; label: string }) {
  return <span className={`core-status-pill core-status-${tone}`}>{label}</span>;
}

export function coreUserSyncState(status?: CoreStatus, diagnostics?: CoreDiagnostics, preview?: CoreConfigPreview, loading = false, error?: unknown): CoreUserSyncState {
  const job = status?.apply_job;
  if (job && coreApplyJobInProgress(job.status)) {
    const retry = job.status === 'retrying' && job.retry_count ? `，第 ${job.retry_count}/${job.max_retries || job.retry_count} 次重试` : '';
    return { key: 'syncing', label: '正在同步', headline: '正在同步核心配置', detail: `${applyJobStatusLabel(job.status)}${retry}。完成后会自动更新状态。`, action: '系统正在处理，无需手动操作。', tone: 'warning' };
  }
  if (job?.status === 'failed') {
    return { key: 'failed', label: '同步失败', headline: '自动同步失败', detail: job.detail || job.error || '自动同步未完成。', action: '可点击“重试同步”，或查看高级详情定位问题。', tone: 'error' };
  }
  if (loading) return { key: 'unknown', label: '未知', headline: '正在检查配置状态', detail: '正在读取核心配置同步状态。', action: '稍后刷新状态。', tone: 'neutral' };
  if (error) return { key: 'unknown', label: '未知', headline: '状态无法判断', detail: error instanceof Error ? error.message : String(error), action: '刷新状态；如果持续失败，请查看日志。', tone: 'warning' };
  if (status?.pending_apply_error || preview?.error || diagnostics?.config_valid === false || preview?.reason === 'generated_build_failed' || preview?.reason === 'disk_parse_failed') {
    return { key: 'needs_check', label: '需要检查', headline: '配置需要检查', detail: status?.pending_apply_detail || status?.pending_apply_error || preview?.detail || preview?.error || diagnostics?.config_error || '配置生成、校验或磁盘读取异常。', action: '查看问题详情，修复后再同步。', tone: 'error' };
  }
  if (status?.pending_apply || preview?.pending_apply) {
    return { key: 'waiting', label: '等待同步', headline: '配置等待同步', detail: humanPendingReason(status?.pending_reason || preview?.pending_reason) || '有真实配置变化尚未应用。', action: '可以等待自动同步，或点击“立即同步”。', tone: 'warning' };
  }
  if (preview?.in_sync || diagnostics?.disk_generated_in_sync === true) {
    return { key: 'in_sync', label: '已生效', headline: '核心配置已生效', detail: '数据库生成配置、磁盘配置与已应用状态一致。', action: '无需处理。', tone: 'ok' };
  }
  if ((preview && preview.in_sync === false) || diagnostics?.disk_generated_in_sync === false) {
    return { key: 'needs_check', label: '需要检查', headline: '配置不同步', detail: configSyncReasonLabel(preview?.reason || diagnostics?.sync_reason) || '磁盘配置与数据库生成配置不一致。', action: '点击“查看问题”检查磁盘配置，必要时重新同步。', tone: 'warning' };
  }
  return { key: 'unknown', label: '未知', headline: '状态无法判断', detail: '还没有足够信息判断核心配置是否已生效。', action: '刷新状态或查看诊断。', tone: 'neutral' };
}

function coreApplyButtonLabel(state: CoreUserSyncState): string {
  switch (state.key) {
    case 'failed':
      return '重试同步';
    case 'needs_check':
      return '重新同步';
    case 'waiting':
      return '立即同步';
    case 'in_sync':
      return '重新同步';
    default:
      return '应用配置';
  }
}

function coreApplyJobInProgress(status?: string): boolean {
  return ['queued', 'running', 'retrying'].includes(String(status || '').toLowerCase());
}

function applyJobStatusLabel(status?: string): string {
  switch (String(status || '').toLowerCase()) {
    case 'queued':
      return '排队中';
    case 'running':
      return '执行中';
    case 'retrying':
      return '自动重试中';
    case 'succeeded':
      return '已完成';
    case 'failed':
      return '失败';
    default:
      return status || '未知';
  }
}

function humanPendingReason(reason?: string): string {
  switch (reason) {
    case 'config_changed':
      return '保存的核心配置变化正在等待同步。';
    case 'apply_locked':
      return '当前有其他同步任务占用锁，系统会自动重试。';
    case 'apply_timeout':
      return '上次同步超时，等待重试或手动处理。';
    case 'disk_hash_mismatch':
      return '磁盘配置与数据库生成配置不一致。';
    case 'generated_build_failed':
      return '数据库配置生成失败，需要检查相关配置。';
    default:
      return reason ? `原因：${reason}` : '';
  }
}

export function coreHealthSummary(status?: CoreStatus, diagnostics?: CoreDiagnostics, preview?: CoreConfigPreview, diagnosticsLoading = false, diagnosticsError?: unknown, previewLoading = false, previewError?: unknown): CoreHealthSummary {
  const installed = coreInstalledWithDiagnostics(status, diagnostics);
  const managed = status?.managed ?? diagnostics?.managed;
  const serviceStatus = status?.status || diagnostics?.service_status;
  const sync = configSyncState(preview, previewLoading, previewError);
  const ports = coreListeningDiagnostics(status, diagnostics);
  const missingPorts = ports.filter((port) => !port.listening);
  const diagnosticState = coreDiagnosticsSummary(diagnostics, diagnosticsLoading, diagnosticsError);

  if (!installed || diagnostics?.service_status === 'not_installed') {
    return { tone: 'error', label: '需要安装', headline: '核心未安装', detail: '系统中没有可用核心，当前无法应用配置或监听端口。', nextAction: '先安装核心，再应用配置。' };
  }
  if (serviceStatus && serviceStatus !== 'running' && serviceStatus !== 'not_managed') {
    return { tone: 'error', label: '服务异常', headline: '核心未运行', detail: `服务状态：${serviceLabel(serviceStatus)}。`, nextAction: '先查看诊断建议，必要时重启核心或重新应用配置。' };
  }
  if (diagnostics?.config_exists === false) {
    return { tone: 'error', label: '配置缺失', headline: '配置文件不存在', detail: '磁盘上没有找到核心配置文件。', nextAction: '点击“应用配置”重新写入配置。' };
  }
  if (diagnostics?.config_valid === false) {
    return { tone: 'error', label: '配置错误', headline: '配置校验失败', detail: diagnostics.config_error || '生成的配置未通过核心校验。', nextAction: '查看诊断详情，修复配置后重新应用。' };
  }
  if (managed === false || serviceStatus === 'not_managed') {
    return { tone: 'warning', label: '未托管', headline: '核心未由系统托管', detail: '系统服务托管状态异常，面板可能无法稳定重启或停止核心。', nextAction: '确认 systemd 服务后再执行维护操作。' };
  }
  const userSync = coreUserSyncState(status, diagnostics, preview, previewLoading, previewError);
  if (userSync.key === 'syncing') {
    return { tone: 'warning', label: '正在同步', headline: '正在同步核心配置', detail: userSync.detail, nextAction: userSync.action };
  }
  if (userSync.key === 'failed') {
    return { tone: 'error', label: '同步失败', headline: '自动同步失败', detail: userSync.detail, nextAction: userSync.action };
  }
  if (userSync.key === 'needs_check') {
    return { tone: userSync.tone === 'error' ? 'error' : 'warning', label: '需要检查', headline: userSync.headline, detail: userSync.detail, nextAction: userSync.action };
  }
  if (status?.pending_apply || preview?.pending_apply) {
    return { tone: 'warning', label: '等待同步', headline: '配置等待同步', detail: userSync.detail, nextAction: userSync.action };
  }
  if (sync.ok === false || diagnostics?.disk_generated_in_sync === false) {
    return { tone: 'warning', label: '需要应用', headline: '配置不同步', detail: sync.detail || '磁盘配置与数据库生成配置不一致。', nextAction: '点击“应用配置”同步磁盘配置。' };
  }
  if (missingPorts.length || diagnostics?.missing_listeners?.length) {
    const count = missingPorts.length || diagnostics?.missing_listeners?.length || 0;
    return { tone: 'warning', label: '端口异常', headline: '存在未监听端口', detail: `有 ${count} 个入站端口未监听。`, nextAction: '查看监听端口区和诊断建议，确认服务、防火墙和配置。' };
  }
  if (diagnosticState.tone === 'error') {
    return { tone: 'error', label: '诊断异常', headline: '诊断发现错误', detail: diagnosticState.detail || '核心诊断未通过。', nextAction: recommendedAction(diagnostics, diagnosticState) };
  }
  if (diagnosticState.tone === 'warning') {
    return { tone: 'warning', label: '需要关注', headline: '存在需要关注的问题', detail: diagnosticState.detail ? diagnosticWarningLabel(diagnosticState.detail) : '诊断仍在检查或存在非阻断问题。', nextAction: recommendedAction(diagnostics, diagnosticState) };
  }
  return { tone: 'ok', label: '运行正常', headline: '核心运行正常', detail: '核心已安装、服务运行、配置同步且端口监听状态正常。', nextAction: '无需处理；变更节点或路由后再应用配置。' };
}

export function corePortSummary(ports: ReturnType<typeof coreListeningDiagnostics>): string {
  if (!ports.length) return '暂无监听端口数据。';
  const missing = ports.filter((port) => !port.listening).length;
  if (missing) return `${missing} 个端口未监听，请优先检查服务日志和防火墙。`;
  return `${ports.length} 个端口监听正常。`;
}

export function coreInstalledWithDiagnostics(status?: CoreStatus, diagnostics?: CoreDiagnostics): boolean {
  if (typeof status?.installed === 'boolean') return status.installed;
  if (hasCoreInstallSignal(status)) return isCoreInstalled(status);
  return Boolean(diagnostics?.installed);
}

function hasCoreInstallSignal(status?: CoreStatus): boolean {
  return isKnownCoreSignal(status?.version) || isKnownCoreSignal(status?.status);
}

function isKnownCoreSignal(value?: string): boolean {
  const signal = String(value || '').trim().toLowerCase();
  return Boolean(signal && signal !== 'unknown');
}

function diagnosticChecksForPanel(diagnostics: CoreDiagnostics | undefined, loading: boolean, error: unknown): Array<{ label: string; value: string; ok?: boolean }> {
  if (loading) {
    return coreDiagnosticCheckLabels().map((label) => ({ label, value: '正在检查' }));
  }
  if (error) {
    return coreDiagnosticCheckLabels().map((label) => ({ label, value: '加载失败' }));
  }
  if (!diagnostics) {
    return coreDiagnosticCheckLabels().map((label) => ({ label, value: '未知' }));
  }
  return coreDiagnosticChecks(diagnostics);
}

function coreDiagnosticCheckLabels(): string[] {
  return ['安装', 'systemd 托管', '服务状态', '配置校验', '配置同步', '端口监听'];
}

function issueSummary(diagnostics: CoreDiagnostics | undefined, summary: ReturnType<typeof coreDiagnosticsSummary>): string {
  if (summary.detail) return diagnosticWarningLabel(summary.detail);
  if (diagnostics?.missing_listeners?.length) return `缺失 ${diagnostics.missing_listeners.length} 个监听端口`;
  if (diagnostics?.warnings?.length) return diagnosticWarningLabel(diagnostics.warnings[0]);
  return summary.label;
}

function recommendedAction(diagnostics: CoreDiagnostics | undefined, summary: ReturnType<typeof coreDiagnosticsSummary>): string {
  const action = coreDiagnosticActions(diagnostics)[0];
  if (action) return formatDiagnosticAction(action).message;
  if (diagnostics?.suggestions?.[0]) return diagnostics.suggestions[0];
  if (summary.tone === 'error') return '按错误提示修复后重新应用配置。';
  if (summary.tone === 'warning') return '检查诊断详情，必要时重新应用配置。';
  return '无需处理。';
}

export function coreStatusMetrics(status?: CoreStatus, fallbackVersion?: string): Array<{ label: string; value: string }> {
  const installed = isCoreInstalled(status);
  return [
    { label: '安装', value: installed ? '已安装' : '未安装' },
    { label: '托管', value: status?.managed ? '已托管' : '未托管' },
    { label: '状态', value: serviceLabel(status?.status) },
    { label: '版本', value: versionLabel(status?.version || fallbackVersion) },
    { label: '内存', value: formatBytes(status?.memory_rss_bytes) },
    { label: '运行时长', value: status?.uptime || '-' },
    { label: '连接', value: String(status?.active_connections || 0) },
    { label: '配置路径', value: status?.config_path || '-' },
  ];
}

export function singboxListeningDiagnostics(status?: CoreStatus) {
  return coreListeningDiagnostics(status);
}

export function coreListeningDiagnostics(status?: CoreStatus, diagnostics?: CoreDiagnostics) {
  const source = status?.listening_ports?.length ? status.listening_ports : diagnostics?.expected_listeners || [];
  return source.map((item) => {
    const transport = String(item.transport || item.network || '-');
    const network = String(item.network || '');
    const detail = listenerDetail(item);
    return {
      inboundId: Number(item.inbound_id || 0),
      protocol: item.protocol || '-',
      port: Number(item.port || 0),
      transport,
      ...(network && network !== transport ? { network } : {}),
      ...(item.security ? { security: String(item.security) } : {}),
      ...(detail !== '-' ? { detail } : {}),
      listening: Boolean(item.listening),
    };
  });
}

function listenerDetail(item: { path?: string; grpc_service_name?: string }) {
  if (item.grpc_service_name) return item.grpc_service_name;
  if (item.path) return item.path;
  return '-';
}

export function configSyncState(preview?: CoreConfigPreview, loading = false, error?: unknown): { ok?: boolean; label: string; detail?: string } {
  if (loading) return { label: '正在检查配置同步状态' };
  if (error) return { ok: false, label: '生成配置预览失败', detail: error instanceof Error ? error.message : String(error) };
  if (!preview) return { label: '配置同步状态未知' };
  if (preview.pending_apply) {
    const hashes = [preview.applied_config_hash ? `applied: ${preview.applied_config_hash}` : '', preview.generated?.hash ? `generated: ${preview.generated.hash}` : ''].filter(Boolean).join(' · ');
    return { ok: false, label: '有更改待应用', detail: hashes || '保存的更改需要应用配置后生效' };
  }
  if (preview.in_sync) return { ok: true, label: '磁盘配置与数据库生成配置一致', detail: preview.generated?.hash || preview.disk?.hash };
  const reason = preview.reason ? `原因：${configSyncReasonLabel(preview.reason)}` : '';
  const hashDetail = [preview.disk?.hash ? `disk: ${preview.disk.hash}` : '', preview.generated?.hash ? `generated: ${preview.generated.hash}` : ''].filter(Boolean).join(' · ');
  const detail = [reason, preview.disk?.detail || preview.generated?.detail || hashDetail].filter(Boolean).join(' · ');
  return { ok: false, label: '磁盘配置与数据库生成配置不一致', detail };
}

export function configSyncReasonLabel(reason?: string): string {
  switch (reason) {
    case 'disk_missing':
      return '磁盘配置不存在';
    case 'generated_build_failed':
      return '数据库生成配置失败';
    case 'hash_mismatch':
      return '配置 hash 不一致';
    case 'disk_parse_failed':
      return '磁盘配置解析失败';
    default:
      return reason || '未知原因';
  }
}

export function singboxDiagnosticsSummary(diagnostics?: CoreDiagnostics, loading = false, error?: unknown): { tone: 'ok' | 'warning' | 'error'; label: string; detail?: string } {
  return coreDiagnosticsSummary(diagnostics, loading, error);
}

export function coreDiagnosticsSummary(diagnostics?: CoreDiagnostics, loading = false, error?: unknown): { tone: 'ok' | 'warning' | 'error'; label: string; detail?: string } {
  if (loading) return { tone: 'warning', label: '正在加载诊断' };
  if (error) return { tone: 'error', label: '诊断加载失败', detail: error instanceof Error ? error.message : String(error) };
  if (!diagnostics) return { tone: 'warning', label: '诊断状态未知' };
  const hardError = !diagnostics.installed || diagnostics.service_status === 'not_installed' || !diagnostics.config_exists || !diagnostics.config_valid || diagnostics.service_status === 'stopped';
  if (hardError) return { tone: 'error', label: '错误', detail: diagnostics.config_error || diagnostics.warnings?.[0] };
  if (diagnostics.warnings?.length || diagnostics.missing_listeners?.length || !diagnostics.disk_generated_in_sync || diagnostics.service_status === 'not_managed') return { tone: 'warning', label: '警告', detail: diagnostics.warnings?.[0] };
  return { tone: 'ok', label: '正常' };
}

export function singboxDiagnosticChecks(diagnostics?: CoreDiagnostics): Array<{ label: string; value: string; ok: boolean }> {
  return coreDiagnosticChecks(diagnostics);
}

export function coreDiagnosticChecks(diagnostics?: CoreDiagnostics): Array<{ label: string; value: string; ok: boolean }> {
  return [
    { label: '安装', value: diagnostics?.installed ? '已安装' : '未安装', ok: Boolean(diagnostics?.installed) },
    { label: 'systemd 托管', value: diagnostics?.managed ? diagnostics.service || '已托管' : '未托管', ok: Boolean(diagnostics?.managed) },
    { label: '服务状态', value: serviceLabel(diagnostics?.service_status), ok: diagnostics?.service_status === 'running' },
    { label: '配置校验', value: diagnostics?.config_valid ? '通过' : '失败', ok: Boolean(diagnostics?.config_valid) },
    { label: '配置同步', value: diagnostics?.disk_generated_in_sync ? '一致' : configSyncReasonLabel(diagnostics?.sync_reason), ok: Boolean(diagnostics?.disk_generated_in_sync) },
    { label: '端口监听', value: diagnostics?.missing_listeners?.length ? `缺失 ${diagnostics.missing_listeners.length} 个` : '完整', ok: !diagnostics?.missing_listeners?.length },
  ];
}

export function coreDiagnosticActions(diagnostics?: CoreDiagnostics): CoreDiagnosticAction[] {
  const actions = diagnostics?.actions?.length ? diagnostics.actions : diagnostics?.suggestion_details || [];
  return Array.isArray(actions) ? actions.filter((action) => Boolean(action?.code && action?.message)) : [];
}

export function diagnosticSuggestionItems(diagnostics?: CoreDiagnostics): string[] {
  const actions = coreDiagnosticActions(diagnostics);
  if (actions.length) return actions.map((action) => formatDiagnosticAction(action).summary);
  return diagnostics?.suggestions || [];
}

export function formatDiagnosticAction(action: CoreDiagnosticAction): { severity: string; category: string; message: string; command?: string; target?: string; summary: string } {
  const severity = diagnosticSeverityLabel(action.severity);
  const category = diagnosticCategoryLabel(action.category);
  const target = [action.inbound_id ? `入站 ${action.inbound_id}` : '', action.port ? `端口 ${action.port}` : ''].filter(Boolean).join(' · ');
  const command = String(action.command || '').trim() || undefined;
  const message = action.message || diagnosticWarningLabel(action.code);
  const summary = [severity, category, target, message, command ? `命令：${command}` : ''].filter(Boolean).join(' · ');
  return { severity, category, message, command, target: target || undefined, summary };
}

function diagnosticSeverityLabel(severity?: string): string {
  switch (severity) {
    case 'error':
      return '错误';
    case 'warning':
      return '警告';
    case 'info':
      return '提示';
    default:
      return severity || '提示';
  }
}

function diagnosticCategoryLabel(category?: string): string {
  switch (category) {
    case 'service':
      return '服务';
    case 'config':
      return '配置';
    case 'listener':
      return '监听';
    case 'log':
      return '日志';
    case 'security':
      return '安全';
    case 'routing':
      return '路由';
    default:
      return category || '诊断';
  }
}

function diagnosticActionToneClass(severity?: string): string {
  switch (severity) {
    case 'error':
      return 'bg-red-100 text-red-700';
    case 'warning':
      return 'bg-amber-100 text-amber-800';
    default:
      return 'bg-sky-100 text-sky-700';
  }
}

export function diagnosticWarningLabel(warning: string): string {
  const labels: Record<string, string> = {
    singbox_not_installed: 'sing-box 未安装',
    singbox_not_systemd_managed: 'sing-box 未被 systemd 托管',
    singbox_service_not_running: 'sing-box 服务未运行',
    singbox_config_missing: '配置文件不存在',
    singbox_config_invalid: 'sing-box check 失败',
    singbox_config_out_of_sync: '磁盘配置与数据库生成配置不一致',
    singbox_missing_listeners: '服务运行但入站端口未监听',
    singbox_inbound_without_enabled_clients: '存在启用入站但没有启用客户端',
    singbox_client_credentials_missing: 'Hysteria2/TUIC 缺少可用客户端凭据',
    shadowtls_handshake_missing: 'ShadowTLS 缺少 handshake/SNI',
    singbox_route_outbound_unavailable: '路由规则引用不可用于 sing-box 的出站',
    singbox_stats_unsupported: 'sing-box 二进制不支持当前统计特性',
    singbox_stats_capability_check_failed: 'sing-box 二进制特性检测失败',
    singbox_generated_config_build_failed: '数据库生成 sing-box 配置失败',
    xray_not_installed: 'Xray 未安装',
    xray_not_systemd_managed: 'Xray 未被 systemd 托管',
    xray_service_not_running: 'Xray 服务未运行',
    xray_config_missing: '配置文件不存在',
    xray_config_invalid: 'xray run -test 失败',
    xray_config_out_of_sync: '磁盘配置与数据库生成配置不一致',
    xray_missing_listeners: '服务运行但入站端口未监听',
    xray_inbound_without_enabled_clients: '存在启用入站但没有启用客户端',
    xray_ws_path_invalid: 'WS/H2 path 配置无效',
    xray_grpc_service_name_default: 'gRPC serviceName 将使用默认值',
    xray_grpc_service_name_invalid: 'gRPC serviceName 配置无效',
    xray_xhttp_path_invalid: 'XHTTP path 配置无效',
    xray_reality_settings_incomplete: 'REALITY 配置不完整',
    xray_tls_certificate_missing: 'TLS 证书配置缺失',
    xray_shadowsocks_credentials_missing: 'Shadowsocks 2022 缺少可用凭据',
    xray_route_outbound_unavailable: '路由规则引用不可用于 Xray 的出站',
    xray_generated_config_build_failed: '数据库生成 Xray 配置失败',
  };
  return labels[warning] || warning;
}

function formatLogs(data: { logs?: string; lines?: string[] } | undefined, emptyMessage: string): string {
  if (!data) return emptyMessage;
  if (Array.isArray(data.lines)) return data.lines.join('\n');
  return data.logs || JSON.stringify(data, null, 2);
}

export function coreActionResult(data: CoreActionResponse, fallback: string): { ok: boolean; message: string; detail?: string; tone?: 'success' | 'error' | 'info' } {
  if (data.accepted || normalizeStatus(data.status) === 'accepted') {
    const label = data.apply_job?.core === 'sing-box' || data.apply_job?.core === 'singbox' ? 'sing-box' : 'Xray';
    return withDetail({
      ok: true,
      message: data.message || `${label} 配置已开始应用`,
      tone: 'info',
    }, data.apply_job?.id ? `job:\n${data.apply_job.id}` : undefined);
  }
  const status = normalizeStatus(data.status);
  const xrayStatus = normalizeStatus(data.xray?.status);
  const singboxReason = data.singbox?.reason === 'not_needed' ? '' : data.singbox?.reason;
  const hasNestedCoreResult = Boolean(data.xray || data.singbox);
  const error = data.error || data.xray?.error || data.xray?.detail || data.xray?.error_output || data.singbox?.error || singboxReason || data.reason;
  const failed =
    isFailureStatus(status) ||
    isFailureStatus(xrayStatus) ||
    data.xray?.applied === false ||
    (!hasNestedCoreResult && data.applied === false) ||
    (data.singbox?.applied === false && data.singbox.reason !== 'not_needed') ||
    Boolean(data.error || data.xray?.error || data.xray?.error_output || data.singbox?.error);
  const listenerWarning = firstListenerWarning(allWarnings(data.post_apply_warnings, data.xray?.post_apply_warnings, data.singbox?.post_apply_warnings, data.warnings, data.xray?.warnings, data.singbox?.warnings));
  const message = failed
    ? error || data.xray?.status || data.status || fallback
    : listenerWarning || (
      data.xray?.status
        ? `${fallback}：${data.xray.status}`
        : data.singbox?.applied === true || data.applied === true
          ? fallback
          : data.status || fallback
    );
  const detail = commandDetail(data, message);
  const tone = listenerWarning && !failed ? 'info' : undefined;
  return withDetail({ ok: !failed, message, tone }, detail);
}

function normalizeStatus(status?: string): string {
  return String(status || '').toLowerCase();
}

export function coreStatusRefetchInterval(visible: boolean) {
  return visible ? 12000 : false;
}

export function isCoreInstalled(status?: { installed?: boolean; version?: string; status?: string }): boolean {
  if (typeof status?.installed === 'boolean') return status.installed;
  const version = String(status?.version || '').trim().toLowerCase();
  if (version && version !== 'unknown' && version !== 'not_installed') return true;
  const serviceStatus = String(status?.status || '').trim().toLowerCase();
  return Boolean(serviceStatus && serviceStatus !== 'unknown' && serviceStatus !== 'not_installed');
}

function isFailureStatus(status: string): boolean {
  return status === 'failed' || status === 'error' || status === 'not_managed' || status.startsWith('failed:') || status.startsWith('error:');
}

function errorMessage(error: unknown, fallback: string) {
  return getAPIErrorMessage(error, fallback);
}

function setActionError(error: unknown, fallback: string, setLastResult: (value: { ok: boolean; message: string }) => void, showToast: (title: string, tone?: 'success' | 'error' | 'info') => void) {
  const message = errorMessage(error, fallback);
  setLastResult({ ok: false, message });
  showToast(message, 'error');
}

function commandDetail(data: CoreActionResponse, message: string) {
  const commands = firstNonEmptyCommands(data.commands_executed, data.xray?.commands_executed, data.singbox?.commands_executed);
  const singboxReason = data.singbox?.reason === 'not_needed' ? '' : data.singbox?.reason;
  const output = data.output || data.xray?.detail || data.xray?.error_output || data.xray?.error || data.singbox?.output || data.singbox?.error || singboxReason || '';
  const supplementalOutput = output && output !== message ? output : '';
  return [commands.length ? `commands:\n${commands.join('\n')}` : '', supplementalOutput ? `detail:\n${supplementalOutput}` : ''].filter(Boolean).join('\n\n') || undefined;
}

function firstNonEmptyCommands(...groups: Array<string[] | undefined>): string[] {
  return groups.find((group) => Array.isArray(group) && group.length > 0) || [];
}

function allWarnings(...groups: Array<string[] | undefined>): string[] {
  return groups.flatMap((group) => Array.isArray(group) ? group : []);
}

function firstListenerWarning(warnings: string[]): string {
  return warnings.find((warning) => warning.startsWith('配置已应用，但端口未监听')) || '';
}

function withDetail<T extends { ok: boolean; message: string }>(result: T, detail?: string): T & { detail?: string } {
  return detail ? { ...result, detail } : result;
}

function validationDetail(data: { warnings?: string[]; inbounds?: number; outbounds?: number; rules?: number }) {
  const summary = [data.inbounds != null ? `入站: ${data.inbounds}` : '', data.outbounds != null ? `出站: ${data.outbounds}` : '', data.rules != null ? `规则: ${data.rules}` : ''].filter(Boolean).join(' · ');
  const warnings = data.warnings?.length ? `警告:\n${data.warnings.join('\n')}` : '';
  return [summary, warnings].filter(Boolean).join('\n\n') || undefined;
}
