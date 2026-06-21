import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronUp, Clock3, ExternalLink, FileKey2, Link2, RefreshCw, RotateCcw, Save, ShieldCheck, ShieldX, Trash2, UploadCloud } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useForm } from 'react-hook-form';
import type { UseFormReturn } from 'react-hook-form';
import { ApiError, getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import type { CertificateOperation, CertificatePreflight, Inbound, ManagedCertificate, Settings, UpdateCheck, UpdateStatus, VersionInfo } from '../api/types';
import { Card, EmptyState, Field, LoadingBlock, SpinnerButton, useConfirm, useToast } from '../components/ui';
import { serviceLabel } from '../lib/format';
import { useI18n } from '../lib/i18n';
import { refreshCertificateApplyDependencies, refreshCertificateOperationDependencies, refreshQueries, refreshQuery, refreshSessionDependencies, refreshSettingsDependencies, refreshUpdateDependencies } from '../lib/queryInvalidation';
import { PageTitle } from './OverviewPage';

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const { showToast } = useToast();
  const { text } = useI18n();
  const [watchUpdateStatus, setWatchUpdateStatus] = useState(false);
  const [showAllSessions, setShowAllSessions] = useState(false);
  const [certDomainsInput, setCertDomainsInput] = useState('');
  const [certEmailInput, setCertEmailInput] = useState('');
  const [certDomainsTouched, setCertDomainsTouched] = useState(false);
  const [certEmailTouched, setCertEmailTouched] = useState(false);
  const [importName, setImportName] = useState('');
  const [importFullchain, setImportFullchain] = useState('');
  const [importKey, setImportKey] = useState('');
  const [selectedCertId, setSelectedCertId] = useState<number | null>(null);
  const [selectedInboundIds, setSelectedInboundIds] = useState<number[]>([]);
  const [appliedSelectionCertId, setAppliedSelectionCertId] = useState<number | null>(null);
  const [preflightResult, setPreflightResult] = useState<CertificatePreflight | null>(null);
  const [certWorkspace, setCertWorkspace] = useState<CertificateWorkspace>('acme');
  const [showUpdateLogs, setShowUpdateLogs] = useState(false);
  const session = useQuery({ queryKey: ['session'], queryFn: api.session, staleTime: 5 * 60_000 });
  const settings = useQuery({ queryKey: ['settings'], queryFn: api.settings, retry: false, staleTime: 60_000 });
  const cert = useQuery({ queryKey: ['cert-status'], queryFn: api.certStatus, retry: false, staleTime: 60_000 });
  const certificates = useQuery({ queryKey: ['certificates'], queryFn: api.certificates, retry: false, staleTime: 60_000 });
  const certificateInbounds = useQuery({ queryKey: ['certificate-inbounds'], queryFn: api.certificateInboundTargets, retry: false, staleTime: 60_000 });
  const updateCheck = useQuery({
    queryKey: ['update-check'],
    queryFn: api.updateCheck,
    enabled: watchUpdateStatus,
    retry: false,
    refetchInterval: () => updateDependencyRefetchInterval(watchUpdateStatus),
  });
  const version = useQuery({
    queryKey: ['version'],
    queryFn: api.version,
    enabled: watchUpdateStatus,
    retry: false,
    refetchInterval: () => updateDependencyRefetchInterval(watchUpdateStatus),
  });
  const updateStatus = useQuery({
    queryKey: ['update-status'],
    queryFn: api.updateStatus,
    refetchInterval: (query) => updateStatusRefetchInterval(query.state.data?.status, watchUpdateStatus),
    staleTime: 30_000,
  });
  const updateLogs = useQuery({
    queryKey: ['update-logs'],
    queryFn: api.updateLogs,
    enabled: watchUpdateStatus,
    retry: false,
    refetchInterval: () => updateDependencyRefetchInterval(watchUpdateStatus),
  });
  const sessions = useQuery({ queryKey: ['sessions'], queryFn: api.sessions, retry: false, staleTime: 60_000 });
  const service = useQuery({
    queryKey: ['service-status'],
    queryFn: api.serviceStatus,
    retry: false,
    staleTime: 30_000,
    refetchInterval: () => updateDependencyRefetchInterval(watchUpdateStatus),
  });
  const form = useForm<Settings>({ values: settings.data || {} });
  const certDomain = form.watch('cert_domain') || cert.data?.domain || '';
  const certEmail = form.watch('cert_email') || cert.data?.email || '';
  const managedCertificates = certificates.data?.certificates || [];
  const tlsInbounds = certificateInbounds.data?.inbounds || [];
  const selectedCertificate = useMemo(() => managedCertificates.find((item) => item.id === selectedCertId) || managedCertificates[0], [managedCertificates, selectedCertId]);
  const certificateOperations = useQuery({
    queryKey: ['certificate-operations', selectedCertificate?.id],
    queryFn: () => api.certificateOperations(selectedCertificate?.id || 0),
    enabled: Boolean(selectedCertificate?.id),
    retry: false,
    staleTime: 30_000,
  });
  useEffect(() => {
    if (watchUpdateStatus && isUpdateTerminal(updateStatus.data?.status)) {
      refreshQueries([updateStatus, updateLogs, service, version, updateCheck]);
      if (updateStatus.data?.status !== 'completed' || version.data?.version) {
        setWatchUpdateStatus(false);
      }
    }
  }, [updateStatus.data?.status, version.data?.version, watchUpdateStatus]);
  useEffect(() => {
    if (watchUpdateStatus && version.data?.version && isUpdateTerminal(updateStatus.data?.status)) {
      refreshQuery(updateCheck);
    }
  }, [updateStatus.data?.status, version.data?.version, watchUpdateStatus]);
  useEffect(() => {
    if (!certDomainsTouched && certDomainsInput !== certDomain) {
      setCertDomainsInput(certDomain);
      setPreflightResult(null);
    }
  }, [certDomain, certDomainsInput, certDomainsTouched]);
  useEffect(() => {
    if (!certEmailTouched && certEmailInput !== certEmail) {
      setCertEmailInput(certEmail);
      setPreflightResult(null);
    }
  }, [certEmail, certEmailInput, certEmailTouched]);
  useEffect(() => {
    const currentCertId = selectedCertificate?.id || null;
    if (shouldClearInboundSelectionForActualCertificate(appliedSelectionCertId, currentCertId, selectedInboundIds.length)) {
      setSelectedInboundIds([]);
    }
    setAppliedSelectionCertId(currentCertId);
  }, [appliedSelectionCertId, selectedCertificate?.id, selectedInboundIds.length]);
  const save = useMutation({
    mutationFn: (values: Settings) => api.saveSettings(settingsPayload(settings.data, values)),
    onSuccess: () => {
      showToast(text('设置已保存，端口、数据库或基础路径变更需要重启服务后生效'), 'success');
      form.setValue('panel_password', '');
      refreshSettingsDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('保存设置失败')), 'error'),
  });
  const saveCert = useMutation({
    mutationFn: (values: Settings) => api.saveSettings(certSettingsPayload(settings.data, values)),
    onSuccess: () => {
      showToast(text('证书配置已保存'), 'success');
      refreshSettingsDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('保存证书配置失败')), 'error'),
  });
  const restart = useMutation({
    mutationFn: api.restart,
    onSuccess: () => showToast(text('重启命令已发送'), 'success'),
    onError: (error) => showToast(errorMessage(error, text('重启失败')), 'error'),
  });
  const issueCert = useMutation({
    mutationFn: () => {
      const payload = certIssuePayload(form.getValues(), cert.data);
      return api.issueCert(payload.domain, payload.email);
    },
    onSuccess: () => {
      showToast(text('证书已获取'), 'success');
      refreshSettingsDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('获取证书失败')), 'error'),
  });
  const preflightCert = useMutation({
    mutationFn: () => api.certificatePreflight(parseDomains(certDomainsInput || certDomain), certEmailInput || certEmail),
    onSuccess: (result) => setPreflightResult(result.preflight),
    onError: (error) => showToast(errorMessage(error, text('预检查失败')), 'error'),
  });
  const createManagedCert = useMutation({
    mutationFn: () => api.createCertificate(parseDomains(certDomainsInput || certDomain), certEmailInput || certEmail),
    onSuccess: (result) => {
      setPreflightResult(result.preflight);
      showToast(text('证书申请已完成'), 'success');
      refreshSettingsDependencies(queryClient);
      refreshCertificateOperationDependencies(queryClient);
    },
    onError: (error) => {
      const preflight = preflightFromAPIError(error);
      if (preflight) setPreflightResult(preflight);
      showToast(errorMessage(error, text('证书申请失败')), 'error');
    },
  });
  const importCert = useMutation({
    mutationFn: () => api.importCertificate({ name: importName, fullchain: importFullchain, private_key: importKey }),
    onSuccess: () => {
      setImportFullchain('');
      setImportKey('');
      showToast(text('证书已导入'), 'success');
      refreshSettingsDependencies(queryClient);
      refreshCertificateOperationDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('导入证书失败')), 'error'),
  });
  const renewCerts = useMutation({
    mutationFn: () => api.renewDueCertificates(30),
    onSuccess: (result) => {
      showToast(`${text('续期检查完成')}：${result.renewal?.renewed?.length || 0} ${text('个已续期')}`, 'success');
      refreshSettingsDependencies(queryClient);
      refreshCertificateOperationDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('续期检查失败')), 'error'),
  });
  const applyCert = useMutation({
    mutationFn: () => api.applyCertificate(selectedCertificate?.id || 0, selectedInboundIds),
    onSuccess: () => {
      showToast(text('证书已应用到入站'), 'success');
      refreshCertificateApplyDependencies(queryClient);
      refreshCertificateOperationDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('应用证书失败')), 'error'),
  });
  const deleteCert = useMutation({
    mutationFn: (id: number) => api.deleteCertificate(id),
    onSuccess: () => {
      showToast(text('证书已删除'), 'success');
      refreshSettingsDependencies(queryClient);
      refreshCertificateOperationDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('删除证书失败')), 'error'),
  });
  const update = useMutation({
    mutationFn: api.update,
    onSuccess: () => {
      setWatchUpdateStatus(true);
      showToast(text('更新命令已发送'), 'success');
      refreshUpdateDependencies(queryClient);
      refreshQuery(updateLogs);
    },
    onError: (error) => showToast(errorMessage(error, text('启动更新失败')), 'error'),
  });
  const revoke = useMutation({
    mutationFn: api.revokeSession,
    onSuccess: () => {
      showToast(text('会话已撤销'), 'success');
      refreshSessionDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('撤销会话失败')), 'error'),
  });
  const revokeOthers = useMutation({
    mutationFn: api.revokeOtherSessions,
    onSuccess: (result) => {
      showToast(`${text('已撤销')} ${result.revoked} ${text('个其他会话')}`, 'success');
      refreshSessionDependencies(queryClient);
    },
    onError: (error) => showToast(errorMessage(error, text('撤销其他会话失败')), 'error'),
  });
  const sessionItems = sessions.data || [];
  const visibleSessions = showAllSessions ? sessionItems : sessionItems.slice(0, defaultVisibleSessions);
  const hiddenSessionCount = Math.max(0, sessionItems.length - visibleSessions.length);
  const waitingForService = watchUpdateStatus && [updateStatus, updateLogs, service, version, updateCheck].some((query) => query.isError);
  const updateSummary = updateStatusSummaryKey(updateStatus.data);
  const checkingUpdate = updateCheck.isFetching || version.isFetching;
  const updatePrimary = updatePrimaryAction(updateCheck.data, updateStatus.data);
  const runUpdateCheck = () => {
    setWatchUpdateStatus(true);
    refreshQueries([updateCheck, version, updateStatus]);
  };

  if (settings.isLoading) return <LoadingBlock />;

  return (
    <div className="page-stack">
      <PageTitle title={text('面板设置')} description={text('管理面板端口、路径、凭据、证书、服务状态、更新与活动会话。')} />
      {session.data?.default_password ? (
        <Card className="border-red-200 bg-red-50 p-4 text-sm text-red-700">
          {text('当前仍在使用默认密码，请尽快修改面板密码。')}
        </Card>
      ) : null}
      <PanelSettingsCard
        form={form}
        settings={settings.data}
        saving={save.isPending}
        restarting={restart.isPending}
        onSubmit={(values) => save.mutate(values)}
        onRefresh={() => refreshQueries([settings, cert, service])}
        onRestart={async () => (await confirm({ title: text('重启 MiGate 服务？'), description: text('服务重启后当前连接可能短暂中断。'), tone: 'danger' })) && restart.mutate()}
        text={text}
      />
      <Card className="p-5">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="section-title">{text('TLS 证书')}</h2>
            <div className="mt-1 text-xs text-panel-muted">{text('管理托管证书、签发流程、导入证书以及 TLS 入站绑定。')}</div>
          </div>
          <SpinnerButton className="btn secondary h-8" loading={renewCerts.isPending} onClick={async () => (await confirm({ title: text('检查并续期证书？'), description: text('30 天内到期的 ACME 证书会尝试续期。') })) && renewCerts.mutate()}>
            <RefreshCw className="h-4 w-4" /> {text('检查续期')}
          </SpinnerButton>
        </div>
        <div className="grid gap-4">
          <CertificateManager
            certificates={managedCertificates}
            tlsInbounds={tlsInbounds}
            selectedCertificate={selectedCertificate}
            selectedInboundIds={selectedInboundIds}
            operations={certificateOperations.data?.operations || []}
            operationsLoading={certificateOperations.isFetching}
            preflight={preflightResult}
            certDomainsInput={certDomainsInput}
            certEmailInput={certEmailInput}
            importName={importName}
            importFullchain={importFullchain}
            importKey={importKey}
            workspace={certWorkspace}
            loading={certificates.isLoading || certificateInbounds.isLoading}
            busy={preflightCert.isPending || createManagedCert.isPending || importCert.isPending || renewCerts.isPending || applyCert.isPending || deleteCert.isPending}
            onWorkspaceChange={setCertWorkspace}
            onDomainsChange={(value) => {
              setCertDomainsTouched(true);
              setCertDomainsInput(value);
              setPreflightResult(null);
            }}
            onEmailChange={(value) => {
              setCertEmailTouched(true);
              setCertEmailInput(value);
              setPreflightResult(null);
            }}
            onImportNameChange={setImportName}
            onImportFullchainChange={setImportFullchain}
            onImportKeyChange={setImportKey}
            onSelectCertificate={(id) => {
              setSelectedCertId(id);
              if (shouldClearInboundSelectionOnCertificateSelect(selectedCertificate?.id || null, id)) {
                setSelectedInboundIds([]);
                setAppliedSelectionCertId(id);
              }
            }}
            onToggleInbound={(id) => setSelectedInboundIds(toggleID(selectedInboundIds, id))}
            onPreflight={() => preflightCert.mutate()}
            onCreate={async () => (await confirm({ title: text('申请 TLS 证书？'), description: text('MiGate 将执行 HTTP-01 预检查和 ACME 签发，可能短暂占用 80 端口。') })) && createManagedCert.mutate()}
            onImport={async () => (await confirm({ title: text('导入 TLS 证书？'), description: text('导入后证书和私钥会写入 /etc/migate/certs。') })) && importCert.mutate()}
            onApply={async () => (await confirm({ title: text('应用证书到入站？'), description: text(`将把当前证书应用到选中的 ${selectedInboundIds.length} 个入站，并重新应用对应核心配置。`) })) && applyCert.mutate()}
            onDelete={async (id) => (await confirm({ title: text('删除证书？'), description: text('仍被入站使用的证书不会被删除。'), tone: 'danger' })) && deleteCert.mutate(id)}
            text={text}
          />
          <details className="core-details rounded-md border border-panel-line bg-panel-soft p-3">
            <summary><span>{text('高级 / 兼容证书接口')}</span><ChevronDown className="h-4 w-4" /></summary>
            <div className="core-details-body">
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label={text('证书域名')}><input placeholder="example.com" {...form.register('cert_domain')} /></Field>
                <Field label={text('证书邮箱')}><input placeholder="admin@example.com" {...form.register('cert_email')} /></Field>
              </div>
              <div className="mt-3 flex flex-wrap justify-end gap-2">
                <SpinnerButton type="button" className="btn secondary h-8" loading={saveCert.isPending} onClick={form.handleSubmit((values) => saveCert.mutate(values))}><Save className="h-4 w-4" /> {text('保存兼容配置')}</SpinnerButton>
                <SpinnerButton className="btn secondary h-8" loading={issueCert.isPending} disabled={!certDomain || !certEmail} onClick={async () => (await confirm({ title: text('获取 TLS 证书？'), description: text('兼容接口会使用 MiGate 原生 ACME HTTP-01 申请证书，并可能占用 80 端口。') })) && issueCert.mutate()}>{text('兼容申请')}</SpinnerButton>
              </div>
            </div>
          </details>
        </div>
      </Card>
      <Card className="p-5">
        <SystemUpdateConsole
          updateCheck={updateCheck.data}
          updateStatus={updateStatus.data}
          version={version.data}
          service={service.data}
          logs={updateLogs.data}
          waitingForService={waitingForService}
          updateSummary={updateSummary}
          checkingUpdate={checkingUpdate}
          updatePending={update.isPending}
          showLogs={showUpdateLogs}
          primaryAction={updatePrimary}
          onPrimaryAction={updatePrimary === 'update' ? async () => (await confirm({ title: text('立即更新 MiGate？'), description: text('更新器将通过 systemd-run 在服务外执行。') })) && update.mutate() : runUpdateCheck}
          onRefreshService={() => refreshQuery(service)}
          onToggleLogs={() => {
            setShowUpdateLogs((value) => !value);
            if (!showUpdateLogs) refreshQuery(updateLogs);
          }}
          onRefreshLogs={() => refreshQuery(updateLogs)}
          text={text}
        />
      </Card>
      <Card className="p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="section-title">{text('活动会话')}</h2>
            <div className="mt-1 text-xs text-panel-muted">{text('最多保留最近')} {maxActiveSessionsLabel} {text('个活动会话')}</div>
          </div>
          <SpinnerButton className="btn danger h-8" loading={revokeOthers.isPending} disabled={sessionItems.length <= 1} onClick={async () => (await confirm({ title: text('撤销其他会话？'), description: text('当前会话会保留，其他设备和浏览器需要重新登录。'), tone: 'danger' })) && revokeOthers.mutate()}>
            <ShieldX className="h-4 w-4" /> {text('撤销其他会话')}
          </SpinnerButton>
        </div>
        <div className="grid gap-2">
          {visibleSessions.map((item) => (
            <div key={item.id} className="client-row">
              <div className="min-w-0">
                <div className="font-medium">{text('会话')} {item.id_prefix}</div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-panel-muted">
                  <span>{text('最后使用')}：{item.last_used || '-'}</span>
                  <span>{text('创建')}：{item.created_at || '-'}</span>
                  <span>{text('过期')}：{item.expires_at || '-'}</span>
                </div>
              </div>
              <SpinnerButton className="btn danger h-8" loading={revoke.isPending} onClick={async () => (await confirm({ title: text('撤销该会话？'), tone: 'danger' })) && revoke.mutate(item.id)}>
                <ShieldX className="h-4 w-4" /> {text('撤销')}
              </SpinnerButton>
            </div>
          ))}
          {hiddenSessionCount > 0 || showAllSessions ? (
            <button type="button" className="btn secondary h-8 w-fit" onClick={() => setShowAllSessions((value) => !value)}>
              {showAllSessions ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              {showAllSessions ? text('收起会话') : `${text('展开全部')} ${sessionItems.length} ${text('个会话')}`}
            </button>
          ) : null}
          {sessionItems.length === 0 ? <div className="text-sm text-panel-muted">{text('暂无会话数据')}</div> : null}
        </div>
      </Card>
    </div>
  );
}

export const defaultVisibleSessions = 5;
export const maxActiveSessionsLabel = 10;

function errorMessage(error: unknown, fallback: string) {
  return getAPIErrorMessage(error, fallback);
}

export function settingsPayload(current: Settings | undefined, values: Settings): Settings {
  return { ...current, ...values, panel_password: values.panel_password || '' };
}

export function certSettingsPayload(current: Settings | undefined, values: Settings): Settings {
  return {
    ...current,
    cert_domain: values.cert_domain || '',
    cert_email: values.cert_email || '',
    panel_password: '',
  };
}

export function certIssuePayload(values: Settings, current?: { domain?: string; email?: string }): { domain: string; email: string } {
  return {
    domain: values.cert_domain || current?.domain || '',
    email: values.cert_email || current?.email || '',
  };
}

export function parseDomains(value: string | string[]): string[] {
  const items = Array.isArray(value) ? value : value.split(/[\s,，]+/);
  return Array.from(new Set(items.map((item) => item.trim().toLowerCase()).filter(Boolean)));
}

export function certificateStatusLabel(status?: string) {
  switch (status) {
    case 'issued':
      return '有效';
    case 'expiring_soon':
      return '即将到期';
    case 'expired':
      return '已过期';
    case 'pending':
      return '处理中';
    case 'failed':
      return '失败';
    default:
      return status || '未知';
  }
}

export function certificateStatusTone(status?: string) {
  if (status === 'issued') return 'text-emerald-700 bg-emerald-50 border-emerald-200';
  if (status === 'expiring_soon') return 'text-amber-800 bg-amber-50 border-amber-200';
  if (status === 'expired' || status === 'failed') return 'text-red-700 bg-red-50 border-red-200';
  return 'text-panel-muted bg-panel-soft border-panel-line';
}

export function preflightFromAPIError(error: unknown): CertificatePreflight | null {
  if (!(error instanceof ApiError)) return null;
  const preflight = error.fields?.preflight;
  if (!preflight || typeof preflight !== 'object') return null;
  const candidate = preflight as Partial<CertificatePreflight>;
  if (typeof candidate.ok !== 'boolean' || !Array.isArray(candidate.checks)) return null;
  return {
    ok: candidate.ok,
    checks: candidate.checks.filter((check): check is CertificatePreflight['checks'][number] => !!check && typeof check === 'object' && typeof (check as { code?: unknown }).code === 'string' && typeof (check as { status?: unknown }).status === 'string'),
  };
}

export function toggleID(ids: number[], id: number) {
  return ids.includes(id) ? ids.filter((item) => item !== id) : [...ids, id];
}

type CertificateWorkspace = 'acme' | 'import' | 'apply';

function PanelSettingsCard({
  form,
  settings,
  saving,
  restarting,
  onSubmit,
  onRefresh,
  onRestart,
  text,
}: {
  form: UseFormReturn<Settings>;
  settings?: Settings;
  saving: boolean;
  restarting: boolean;
  onSubmit: (values: Settings) => void;
  onRefresh: () => void;
  onRestart: () => void;
  text: (value: string) => string;
}) {
  const panelPort = settings?.panel_port ?? '-';
  const webBasePath = settings?.web_base_path || '/';
  const databasePath = settings?.database_path || '-';
  const authState = settings?.has_password ? text('已设置密码') : text('未设置密码');
  return (
    <Card className="p-5">
      <form className="panel-config" onSubmit={form.handleSubmit(onSubmit)}>
        <div className="panel-config-header">
          <div>
            <h2 className="section-title">{text('面板配置')}</h2>
            <div className="mt-1 text-xs text-panel-muted">{text('配置管理面板访问入口、登录凭据和本地数据存储。')}</div>
          </div>
        </div>

        <div className="panel-config-summary">
          <SummaryTile label={text('面板端口')} value={panelPort} sub={text('监听端口')} />
          <SummaryTile label={text('Web 基础路径')} value={webBasePath} sub={text('访问前缀')} />
          <SummaryTile label={text('认证状态')} value={authState} sub={settings?.panel_username || text('当前用户')} tone={settings?.has_password ? 'normal' : 'error'} />
          <SummaryTile label={text('数据库路径')} value={shortPanelPath(databasePath)} sub={text('本地配置库')} />
        </div>

        <div className="panel-config-sections">
          <section className="panel-config-section">
            <div className="panel-config-section-title">{text('访问入口')}</div>
            <div className="settings-field-grid">
              <Field label={text('面板端口')}><input type="number" {...form.register('panel_port', { valueAsNumber: true })} /></Field>
              <Field label={text('Web 基础路径')}><input placeholder="/panel" {...form.register('web_base_path')} /></Field>
            </div>
          </section>

          <section className="panel-config-section">
            <div className="panel-config-section-title">{text('登录凭据')}</div>
            <div className="settings-field-grid">
              <Field label={text('用户名')}><input {...form.register('panel_username')} /></Field>
              <Field label={text('新密码')} help={settings?.has_password ? text('留空表示保留现有密码。') : undefined}><input type="password" autoComplete="new-password" {...form.register('panel_password')} /></Field>
            </div>
          </section>

          <section className="panel-config-section">
            <div className="panel-config-section-title">{text('存储')}</div>
            <div className="settings-field-grid panel-config-storage-grid">
              <Field label={text('数据库路径')}><input {...form.register('database_path')} /></Field>
            </div>
          </section>
        </div>

        <div className="panel-config-actions">
          <button type="button" className="btn secondary" onClick={onRefresh}><RefreshCw className="h-4 w-4" /> {text('刷新')}</button>
          <SpinnerButton type="submit" className="btn primary" loading={saving}><Save className="h-4 w-4" /> {text('保存设置')}</SpinnerButton>
          <SpinnerButton type="button" className="btn danger" loading={restarting} onClick={onRestart}><RotateCcw className="h-4 w-4" /> {text('重启服务')}</SpinnerButton>
        </div>
      </form>
    </Card>
  );
}

function shortPanelPath(value: ReactNode) {
  if (typeof value !== 'string') return value;
  if (value === '-') return value;
  return shortPath(value);
}

export function certificateInventorySummary(certificates: ManagedCertificate[], tlsInbounds: Inbound[]) {
  const counts = certificates.reduce(
    (result, cert) => {
      const status = String(cert.status || '').toLowerCase();
      if (status === 'issued') result.valid += 1;
      else if (status === 'expiring_soon') result.expiring += 1;
      else if (status === 'expired') result.expired += 1;
      else if (status === 'failed') result.failed += 1;
      return result;
    },
    { total: certificates.length, valid: 0, expiring: 0, expired: 0, failed: 0, boundInbounds: 0, usageCount: 0, recommendedAction: '暂无证书，建议先申请 ACME 证书。' },
  );
  counts.boundInbounds = tlsInbounds.filter((inbound) => hasTLSCertificateBinding(inbound)).length;
  counts.usageCount = certificates.reduce((total, cert) => total + (cert.usage_count || 0), 0);
  if (counts.failed > 0 || counts.expired > 0) counts.recommendedAction = '存在失败或已过期证书，建议查看错误并重新申请。';
  else if (counts.expiring > 0) counts.recommendedAction = '存在即将到期证书，建议运行续期检查。';
  else if (counts.total > 0 && counts.boundInbounds === 0) counts.recommendedAction = '已有证书，建议绑定到需要 TLS 的入站。';
  else if (counts.total > 0) counts.recommendedAction = '证书状态正常，定期检查续期即可。';
  return counts;
}

export function inboundTLSValue(inbound: Inbound, key: 'tls_cert_file' | 'tls_key_file' | 'tls_sni') {
  const value = inbound[key];
  return typeof value === 'string' ? value.trim() : '';
}

export function hasTLSCertificateBinding(inbound: Inbound) {
  return Boolean(inboundTLSValue(inbound, 'tls_cert_file') || inboundTLSValue(inbound, 'tls_key_file'));
}

export type InboundCertificateBindingStatus = 'current' | 'other' | 'none';

export function inboundCertificateBindingStatus(inbound: Inbound, certificate?: ManagedCertificate): InboundCertificateBindingStatus {
  const certFile = inboundTLSValue(inbound, 'tls_cert_file');
  const keyFile = inboundTLSValue(inbound, 'tls_key_file');
  if (!certFile && !keyFile) return 'none';
  if (certificate && certFile === certificate.cert_path && keyFile === certificate.key_path) return 'current';
  return 'other';
}

export function shouldClearInboundSelectionOnCertificateSelect(currentId: number | null, nextId: number) {
  return currentId !== nextId;
}

export function shouldClearInboundSelectionForActualCertificate(previousId: number | null, nextId: number | null, selectedCount: number) {
  return selectedCount > 0 && previousId !== nextId;
}

function shortPath(value: string) {
  return value.split('/').filter(Boolean).pop() || value;
}

function CertificateManager({
  certificates,
  tlsInbounds,
  selectedCertificate,
  selectedInboundIds,
  operations,
  operationsLoading,
  preflight,
  certDomainsInput,
  certEmailInput,
  importName,
  importFullchain,
  importKey,
  workspace,
  loading,
  busy,
  onWorkspaceChange,
  onDomainsChange,
  onEmailChange,
  onImportNameChange,
  onImportFullchainChange,
  onImportKeyChange,
  onSelectCertificate,
  onToggleInbound,
  onPreflight,
  onCreate,
  onImport,
  onApply,
  onDelete,
  text,
}: {
  certificates: ManagedCertificate[];
  tlsInbounds: Inbound[];
  selectedCertificate?: ManagedCertificate;
  selectedInboundIds: number[];
  operations: CertificateOperation[];
  operationsLoading: boolean;
  preflight: CertificatePreflight | null;
  certDomainsInput: string;
  certEmailInput: string;
  importName: string;
  importFullchain: string;
  importKey: string;
  workspace: CertificateWorkspace;
  loading: boolean;
  busy: boolean;
  onWorkspaceChange: (value: CertificateWorkspace) => void;
  onDomainsChange: (value: string) => void;
  onEmailChange: (value: string) => void;
  onImportNameChange: (value: string) => void;
  onImportFullchainChange: (value: string) => void;
  onImportKeyChange: (value: string) => void;
  onSelectCertificate: (id: number) => void;
  onToggleInbound: (id: number) => void;
  onPreflight: () => void;
  onCreate: () => void;
  onImport: () => void;
  onApply: () => void;
  onDelete: (id: number) => void;
  text: (value: string) => string;
}) {
  const summary = certificateInventorySummary(certificates, tlsInbounds);
  return (
    <div className="grid gap-4">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <SummaryTile label={text('托管证书')} value={summary.total} sub={text('全部资产')} />
        <SummaryTile label={text('有效 / 临期')} value={`${summary.valid} / ${summary.expiring}`} sub={`${text('已过期')} ${summary.expired}`} />
        <SummaryTile label={text('失败')} value={summary.failed} sub={text('需处理')} tone={summary.failed > 0 ? 'error' : 'normal'} />
        <SummaryTile label={text('TLS 入站绑定')} value={summary.boundInbounds} sub={`${text('使用计数')} ${summary.usageCount}`} />
        <div className="rounded-md border border-teal-200 bg-teal-50 p-3 text-sm text-teal-900 md:col-span-2 xl:col-span-1">
          <div className="text-xs font-semibold text-teal-700">{text('推荐动作')}</div>
          <div className="mt-1 leading-5">{text(summary.recommendedAction)}</div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(360px,0.8fr)]">
        <div className="grid min-w-0 gap-4">
          <section className="rounded-md border border-panel-line">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-panel-line px-3 py-2">
              <div className="text-sm font-semibold text-panel-text">{text('证书资产列表')}</div>
              <div className="text-xs text-panel-muted">{text('选择证书后查看详情和绑定操作')}</div>
            </div>
            <div className="hidden grid-cols-[minmax(180px,1.2fr)_110px_110px_110px_80px_auto] gap-3 border-b border-panel-line px-3 py-2 text-xs font-semibold text-panel-muted lg:grid">
              <span>{text('域名')}</span>
              <span>{text('状态')}</span>
              <span>{text('来源')}</span>
              <span>{text('到期时间')}</span>
              <span>{text('使用')}</span>
              <span>{text('操作')}</span>
            </div>
            {loading ? <div className="p-3 text-sm text-panel-muted">{text('加载中...')}</div> : null}
            {!loading && certificates.length === 0 ? (
              <div className="p-3">
                <EmptyState title={text('暂无托管证书')} description={text('先通过 ACME 申请，或导入现有 PEM 证书。')} />
              </div>
            ) : null}
            {certificates.map((cert) => (
              <div key={cert.id} className={`grid gap-3 border-b border-panel-line px-3 py-3 text-sm last:border-b-0 lg:grid-cols-[minmax(180px,1.2fr)_110px_110px_110px_80px_auto] ${selectedCertificate?.id === cert.id ? 'bg-teal-50/60' : ''}`}>
                <button className="min-w-0 text-left" onClick={() => onSelectCertificate(cert.id)}>
                  <div className="font-medium text-panel-text">{cert.domains?.[0] || cert.name || `#${cert.id}`}</div>
                  <div className="mt-1 break-all text-xs text-panel-muted">{cert.domains?.join(', ') || '-'}</div>
                  {cert.last_error ? <div className="mt-1 break-all text-xs text-red-600">{cert.last_error}</div> : null}
                </button>
                <div><span className={`rounded border px-2 py-0.5 text-xs ${certificateStatusTone(cert.status)}`}>{text(certificateStatusLabel(cert.status))}</span></div>
                <div className="text-panel-muted">{text(certificateSourceLabel(cert.source))}</div>
                <div className="text-panel-muted">{formatDate(cert.not_after)}</div>
                <div className="text-panel-muted">{cert.usage_count || 0}</div>
                <button className="icon-button h-8 w-8 text-panel-muted" title={text('删除证书')} onClick={() => onDelete(cert.id)}><Trash2 className="h-4 w-4" /></button>
              </div>
            ))}
          </section>
          <section className="rounded-md border border-panel-line bg-panel-soft p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="text-sm font-semibold text-panel-text">{text('证书操作')}</div>
                <div className="mt-1 text-xs text-panel-muted">{text('ACME 申请、手动导入和应用到 TLS 入站分步执行。')}</div>
              </div>
              <div className="segmented-control" aria-label={text('证书操作类型')}>
                <button type="button" className={workspace === 'acme' ? 'active' : ''} title={text('ACME 申请')} onClick={() => onWorkspaceChange('acme')}><FileKey2 className="h-4 w-4" /></button>
                <button type="button" className={workspace === 'import' ? 'active' : ''} title={text('手动导入')} onClick={() => onWorkspaceChange('import')}><UploadCloud className="h-4 w-4" /></button>
                <button type="button" className={workspace === 'apply' ? 'active' : ''} title={text('应用到入站')} onClick={() => onWorkspaceChange('apply')}><Link2 className="h-4 w-4" /></button>
              </div>
            </div>
            {workspace === 'acme' ? (
              <ACMEWorkspace
                preflight={preflight}
                domainsInput={certDomainsInput}
                emailInput={certEmailInput}
                busy={busy}
                onDomainsChange={onDomainsChange}
                onEmailChange={onEmailChange}
                onPreflight={onPreflight}
                onCreate={onCreate}
                text={text}
              />
            ) : null}
            {workspace === 'import' ? (
              <ImportWorkspace
                importName={importName}
                importFullchain={importFullchain}
                importKey={importKey}
                busy={busy}
                onImportNameChange={onImportNameChange}
                onImportFullchainChange={onImportFullchainChange}
                onImportKeyChange={onImportKeyChange}
                onImport={onImport}
                text={text}
              />
            ) : null}
            {workspace === 'apply' ? (
              <ApplyWorkspace
                selectedCertificate={selectedCertificate}
                selectedInboundIds={selectedInboundIds}
                tlsInbounds={tlsInbounds}
                busy={busy}
                onToggleInbound={onToggleInbound}
                onApply={onApply}
                text={text}
              />
            ) : null}
          </section>
        </div>
        <CertificateDetails certificate={selectedCertificate} operations={operations} loading={operationsLoading} text={text} />
      </div>
    </div>
  );
}

function SummaryTile({ label, value, sub, tone = 'normal' }: { label: string; value: ReactNode; sub: string; tone?: 'normal' | 'error' }) {
  return (
    <div className={`rounded-md border p-3 ${tone === 'error' ? 'border-red-200 bg-red-50' : 'border-panel-line bg-panel-soft'}`}>
      <div className="text-xs font-semibold text-panel-muted">{label}</div>
      <div className={`summary-tile-value mt-1 text-2xl font-bold ${tone === 'error' ? 'text-red-700' : 'text-panel-text'}`}>{value}</div>
      <div className="mt-1 text-xs text-panel-muted">{sub}</div>
    </div>
  );
}

function ACMEWorkspace({ preflight, domainsInput, emailInput, busy, onDomainsChange, onEmailChange, onPreflight, onCreate, text }: {
  preflight: CertificatePreflight | null;
  domainsInput: string;
  emailInput: string;
  busy: boolean;
  onDomainsChange: (value: string) => void;
  onEmailChange: (value: string) => void;
  onPreflight: () => void;
  onCreate: () => void;
  text: (value: string) => string;
}) {
  const canRequest = Boolean(parseDomains(domainsInput).length && emailInput);
  return (
    <div className="grid gap-4">
      <div className="settings-field-grid">
        <Field label={text('申请域名 / SAN')} help={text('多个域名可用逗号或空格分隔。')}>
          <input value={domainsInput} onChange={(event) => onDomainsChange(event.target.value)} placeholder="example.com www.example.com" />
        </Field>
        <Field label={text('ACME 邮箱')}>
          <input value={emailInput} onChange={(event) => onEmailChange(event.target.value)} placeholder="admin@example.com" />
        </Field>
      </div>
      <div className="grid gap-2 rounded-md border border-panel-line bg-panel-surface p-3 text-sm">
        <StepRow index={1} label={text('填写域名/SAN 和邮箱')} done={canRequest} />
        <StepRow index={2} label={text('运行预检查')} done={Boolean(preflight)} />
        <StepRow index={3} label={text('查看预检查结果')} done={Boolean(preflight?.ok)} warning={Boolean(preflight && !preflight.ok)} />
        <StepRow index={4} label={text('确认申请证书')} done={false} />
      </div>
      {preflight ? <PreflightResult preflight={preflight} text={text} /> : null}
      <div className="flex flex-wrap gap-2">
        <SpinnerButton className="btn secondary h-8" loading={busy} disabled={!canRequest} onClick={onPreflight}><ShieldCheck className="h-4 w-4" /> {text('运行预检查')}</SpinnerButton>
        <SpinnerButton className="btn primary h-8" loading={busy} disabled={!canRequest || !preflight?.ok} onClick={onCreate}><FileKey2 className="h-4 w-4" /> {text('确认申请证书')}</SpinnerButton>
      </div>
    </div>
  );
}

function ImportWorkspace({ importName, importFullchain, importKey, busy, onImportNameChange, onImportFullchainChange, onImportKeyChange, onImport, text }: {
  importName: string;
  importFullchain: string;
  importKey: string;
  busy: boolean;
  onImportNameChange: (value: string) => void;
  onImportFullchainChange: (value: string) => void;
  onImportKeyChange: (value: string) => void;
  onImport: () => void;
  text: (value: string) => string;
}) {
  return (
    <div className="grid gap-3">
      <Field label={text('导入名称')}><input value={importName} onChange={(event) => onImportNameChange(event.target.value)} placeholder="example.com" /></Field>
      <div className="grid gap-3 md:grid-cols-2">
        <Field label={text('Fullchain PEM')}><textarea className="min-h-32" value={importFullchain} onChange={(event) => onImportFullchainChange(event.target.value)} /></Field>
        <Field label={text('Private Key PEM')}><textarea className="min-h-32" value={importKey} onChange={(event) => onImportKeyChange(event.target.value)} /></Field>
      </div>
      <div className="flex justify-end">
        <SpinnerButton className="btn primary h-8" loading={busy} disabled={!importFullchain || !importKey} onClick={onImport}><UploadCloud className="h-4 w-4" /> {text('导入证书')}</SpinnerButton>
      </div>
    </div>
  );
}

function ApplyWorkspace({ selectedCertificate, selectedInboundIds, tlsInbounds, busy, onToggleInbound, onApply, text }: {
  selectedCertificate?: ManagedCertificate;
  selectedInboundIds: number[];
  tlsInbounds: Inbound[];
  busy: boolean;
  onToggleInbound: (id: number) => void;
  onApply: () => void;
  text: (value: string) => string;
}) {
  return (
    <div className="grid gap-3">
      <div className="rounded-md border border-panel-line bg-panel-surface p-3 text-sm">
        <div className="font-semibold text-panel-text">{text('当前证书')}</div>
        <div className="mt-1 break-all text-panel-muted">{selectedCertificate?.domains?.join(', ') || selectedCertificate?.name || text('未选择证书')}</div>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {tlsInbounds.map((inbound) => {
          const bindingStatus = inboundCertificateBindingStatus(inbound, selectedCertificate);
          const tlsSNI = inboundTLSValue(inbound, 'tls_sni');
          const certFile = inboundTLSValue(inbound, 'tls_cert_file');
          const keyFile = inboundTLSValue(inbound, 'tls_key_file');
          const bindingHint = certFile || keyFile ? [certFile && shortPath(certFile), keyFile && shortPath(keyFile)].filter(Boolean).join(' / ') : text('无 TLS 证书路径');
          return (
            <label key={inbound.id} className="flex min-w-0 items-start gap-2 rounded border border-panel-line bg-panel-surface px-3 py-2 text-sm">
              <input className="mt-1 shrink-0" type="checkbox" checked={selectedInboundIds.includes(inbound.id)} onChange={() => onToggleInbound(inbound.id)} />
              <span className="min-w-0 flex-1">
                <span className="block break-words font-medium text-panel-text">{inbound.remark || inbound.protocol} · {inbound.protocol} · {inbound.port}</span>
                <span className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                  <span className={`rounded border px-2 py-0.5 ${bindingStatus === 'current' ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : bindingStatus === 'other' ? 'border-amber-200 bg-amber-50 text-amber-800' : 'border-panel-line bg-panel-soft text-panel-muted'}`}>
                    {text(bindingStatus === 'current' ? '已绑定当前证书' : bindingStatus === 'other' ? '已绑定其他证书' : '未绑定证书')}
                  </span>
                  <span className="min-w-0 break-all text-panel-muted">{tlsSNI ? `${text('SNI')}：${tlsSNI}` : `${text('证书')}：${bindingHint}`}</span>
                </span>
              </span>
            </label>
          );
        })}
      </div>
      {tlsInbounds.length === 0 ? <EmptyState title={text('暂无可绑定的 TLS 入站')} /> : null}
      <div className="flex justify-end">
        <SpinnerButton className="btn primary h-8" loading={busy} disabled={!selectedCertificate || selectedInboundIds.length === 0} onClick={onApply}>
          <Link2 className="h-4 w-4" /> {text(`应用到选中的 ${selectedInboundIds.length} 个入站`)}
        </SpinnerButton>
      </div>
    </div>
  );
}

function CertificateDetails({ certificate, operations, loading, text }: { certificate?: ManagedCertificate; operations: CertificateOperation[]; loading: boolean; text: (value: string) => string }) {
  if (!certificate) {
    return <div className="rounded-md border border-panel-line bg-panel-soft p-4"><EmptyState title={text('未选择证书')} description={text('选择左侧证书后查看路径、指纹、绑定和操作记录。')} /></div>;
  }
  const boundInbounds = certificate.usages || [];
  return (
    <aside className="grid min-w-0 gap-4">
      <section className="rounded-md border border-panel-line bg-panel-soft p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-semibold text-panel-text">{text('证书详情')}</div>
          <span className={`rounded border px-2 py-0.5 text-xs ${certificateStatusTone(certificate.status)}`}>{text(certificateStatusLabel(certificate.status))}</span>
        </div>
        <div className="grid gap-2 text-xs text-panel-muted">
          <DetailLine label={text('cert_path')} value={certificate.cert_path} />
          <DetailLine label={text('key_path')} value={certificate.key_path} />
          <DetailLine label={text('fingerprint')} value={certificate.fingerprint || '-'} />
          <DetailLine label={text('serial')} value={certificate.serial || '-'} />
          <DetailLine label={text('到期时间')} value={formatDate(certificate.not_after)} />
          {certificate.last_error ? <DetailLine label={text('最后错误')} value={certificate.last_error} tone="error" /> : null}
        </div>
      </section>
      <section className="rounded-md border border-panel-line bg-panel-soft p-4">
        <div className="mb-3 text-sm font-semibold text-panel-text">{text('绑定的入站')}</div>
        <div className="grid gap-2">
          {boundInbounds.map((inbound) => (
            <div key={inbound.id} className="rounded border border-panel-line bg-panel-surface px-3 py-2 text-sm">
              <div className="font-medium text-panel-text">{inbound.remark || inbound.protocol}</div>
              <div className="mt-1 text-xs text-panel-muted">{inbound.protocol} · {inbound.port}</div>
            </div>
          ))}
          {boundInbounds.length === 0 ? <div className="text-sm text-panel-muted">{text('暂无入站使用该证书')}</div> : null}
        </div>
      </section>
      <section className="rounded-md border border-panel-line bg-panel-soft p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <div className="text-sm font-semibold text-panel-text">{text('最近操作记录')}</div>
          {loading ? <span className="text-xs text-panel-muted">{text('加载中...')}</span> : null}
        </div>
        <div className="grid gap-2">
          {operations.map((operation) => (
            <div key={operation.id} className="rounded border border-panel-line bg-panel-surface px-3 py-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-panel-text">{text(operation.type)}</span>
                <span className={`rounded border px-2 py-0.5 ${certificateOperationTone(operation.status)}`}>{text(operation.status)}</span>
              </div>
              <div className="mt-1 text-panel-muted">{formatDateTime(operation.created_at)}</div>
              {operation.message || operation.detail ? <div className="mt-1 break-all text-panel-muted" data-no-i18n>{certificateOperationMessageLabel(operation, text)}</div> : null}
              {operation.code ? <div className="mt-1 break-all text-panel-muted">{operation.code}</div> : null}
            </div>
          ))}
          {!loading && operations.length === 0 ? <div className="text-sm text-panel-muted">{text('暂无操作记录')}</div> : null}
        </div>
      </section>
    </aside>
  );
}

function DetailLine({ label, value, tone = 'normal' }: { label: string; value: string; tone?: 'normal' | 'error' }) {
  return (
    <div className="grid gap-1">
      <span className="font-semibold text-panel-text">{label}</span>
      <span className={`break-all ${tone === 'error' ? 'text-red-600' : ''}`}>{value || '-'}</span>
    </div>
  );
}

function StepRow({ index, label, done, warning = false }: { index: number; label: string; done: boolean; warning?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`inline-grid h-6 w-6 shrink-0 place-items-center rounded-full text-xs font-semibold ${warning ? 'bg-amber-100 text-amber-800' : done ? 'bg-emerald-100 text-emerald-700' : 'bg-panel-soft text-panel-muted'}`}>{index}</span>
      <span className="text-panel-text">{label}</span>
    </div>
  );
}

function PreflightResult({ preflight, text }: { preflight: CertificatePreflight; text: (value: string) => string }) {
  return (
    <div className={`rounded-md border p-3 ${preflight.ok ? 'border-emerald-200 bg-emerald-50' : 'border-amber-200 bg-amber-50'}`}>
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
        {preflight.ok ? <CheckCircle2 className="h-4 w-4 text-emerald-700" /> : <AlertTriangle className="h-4 w-4 text-amber-700" />}
        <span>{text(preflight.ok ? '预检查通过' : '预检查存在问题')}</span>
      </div>
      <div className="grid gap-2">
        {preflight.checks.map((check) => (
          <div key={`${check.code}-${check.detail}`} className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`rounded border px-2 py-0.5 ${certificateStatusTone(check.status === 'failed' ? 'failed' : check.status === 'warning' ? 'expiring_soon' : 'issued')}`}>{text(check.status)}</span>
            <span className="font-medium text-panel-text">{check.code}</span>
            {check.message ? <span className="text-panel-muted">{text(check.message)}</span> : null}
            {check.detail ? <span className="break-all text-panel-muted" data-no-i18n>{check.detail}</span> : null}
          </div>
        ))}
      </div>
    </div>
  );
}

function SystemUpdateConsole({
  updateCheck,
  updateStatus,
  version,
  service,
  logs,
  waitingForService,
  updateSummary,
  checkingUpdate,
  updatePending,
  showLogs,
  primaryAction,
  onPrimaryAction,
  onRefreshService,
  onToggleLogs,
  onRefreshLogs,
  text,
}: {
  updateCheck?: UpdateCheck;
  updateStatus?: UpdateStatus;
  version?: VersionInfo;
  service?: { service: string; status: string; detail?: string };
  logs?: { logs?: string; lines?: string[]; path?: string };
  waitingForService: boolean;
  updateSummary: string;
  checkingUpdate: boolean;
  updatePending: boolean;
  showLogs: boolean;
  primaryAction: 'check' | 'update';
  onPrimaryAction: () => void;
  onRefreshService: () => void;
  onToggleLogs: () => void;
  onRefreshLogs: () => void;
  text: (value: string) => string;
}) {
  const inProgress = isUpdateInProgress(updateStatus?.status);
  const currentVersion = version?.version || updateCheck?.current_version || updateStatus?.current_version || '-';
  const latestVersion = updateCheck?.latest_version || updateStatus?.target_version || '-';
  const failed = String(updateStatus?.status || '').toLowerCase() === 'failed';
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="section-title">{text('系统更新控制台')}</h2>
          <div className="mt-1 text-xs text-panel-muted">{text('检查版本、执行在线升级，并在失败时查看回滚与健康检查结果。')}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <SpinnerButton className="btn primary" loading={checkingUpdate || updatePending} disabled={inProgress} onClick={onPrimaryAction}>
            {primaryAction === 'update' ? <UploadCloud className="h-4 w-4" /> : <RefreshCw className="h-4 w-4" />}
            {text(inProgress ? '更新中' : primaryAction === 'update' ? '立即更新' : '检查更新')}
          </SpinnerButton>
          <button className="btn secondary" onClick={onRefreshService}><RefreshCw className="h-4 w-4" /> {text('刷新服务状态')}</button>
          {showLogs ? <button className="btn secondary" onClick={onRefreshLogs}><RefreshCw className="h-4 w-4" /> {text('刷新日志')}</button> : null}
          <button className="btn secondary" onClick={onToggleLogs}>{showLogs ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />} {text(showLogs ? '收起日志' : '加载日志')}</button>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <SummaryTile label={text('当前版本')} value={currentVersion} sub={text('本机运行版本')} />
        <SummaryTile label={text('最新版本')} value={latestVersion} sub={updateCheck?.release_name || text('等待检查')} />
        <SummaryTile label={text('可更新')} value={text(updateCheck?.update_available ? '是' : '否')} sub={updateCheck?.status || text('检查后更新')} tone={updateCheck?.update_available ? 'normal' : 'normal'} />
        <SummaryTile label={text('MiGate 服务')} value={text(serviceLabel(service?.status))} sub={service?.service || 'migate'} tone={service?.status && service.status !== 'running' ? 'error' : 'normal'} />
        <SummaryTile label={text('更新状态')} value={text(updateStatus?.status || 'idle')} sub={rollbackSummary(updateStatus, text)} tone={failed ? 'error' : 'normal'} />
      </div>

      {inProgress ? (
        <div className="rounded-md border border-sky-200 bg-sky-50 p-4 text-sm text-sky-900">
          <div className="flex items-center gap-2 font-semibold"><Clock3 className="h-4 w-4" /> {text('更新进行中')}</div>
          <div className="mt-1">{updateStatusMessageLabel(updateStatus?.message || '正在执行更新任务，请等待状态刷新。', text)}</div>
        </div>
      ) : null}

      {failed || waitingForService || updateSummary ? (
        <div className={`rounded-md border p-4 text-sm ${failed ? 'border-red-200 bg-red-50 text-red-800' : 'border-emerald-200 bg-emerald-50 text-emerald-800'}`}>
          <div className="font-semibold">{text(failed ? '最近更新失败' : '最近更新结果')}</div>
          {updateSummary ? <div className="mt-1">{text(updateSummary)}</div> : null}
          {waitingForService ? <div className="mt-1">{text('正在等待服务恢复')}</div> : null}
          {updateStatus?.message ? <div className="mt-1">{updateStatusMessageLabel(updateStatus.message, text)}</div> : null}
          <div className="mt-2 grid gap-1 text-xs">
            <div>{text('回滚')}：{rollbackSummary(updateStatus, text)}</div>
            <div>{text('健康检查')}：<span data-no-i18n>{updateStatus?.health_check || '-'}</span></div>
          </div>
        </div>
      ) : null}

      <div className="grid gap-2 rounded-md border border-panel-line bg-panel-soft p-4 text-sm text-panel-muted md:grid-cols-2">
        <div>{text('服务详情')}：<span data-no-i18n>{service?.detail ? serviceDetailLabel(service.detail, text) : '-'}</span></div>
        <div>{text('日志路径')}：<span data-no-i18n>{logs?.path || '/var/log/migate-update.log'}</span></div>
        {updateCheck?.release_url ? <a className="inline-flex w-fit items-center gap-1 text-teal-700" href={updateCheck.release_url} target="_blank" rel="noreferrer">{text('发布说明')} <ExternalLink className="h-3 w-3" /></a> : null}
      </div>

      {showLogs ? (
        <details className="core-details rounded-md border border-panel-line bg-panel-soft p-3" open>
          <summary><span>{text('更新日志')}</span><ChevronDown className="h-4 w-4" /></summary>
          <div className="core-details-body">
            <pre className="code-block core-code-block" data-no-i18n>{formatUpdateLogs(logs, text('点击“加载日志”查看最近更新日志。'))}</pre>
          </div>
        </details>
      ) : null}
    </div>
  );
}

function formatDate(value?: string) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString();
}

function formatDateTime(value?: string) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function certificateSourceLabel(source?: string) {
  if (source === 'acme') return 'ACME';
  if (source === 'import') return '导入';
  return source || '未知';
}

function certificateOperationTone(status?: string) {
  const normalized = String(status || '').toLowerCase();
  if (['success', 'completed', 'ok'].includes(normalized)) return 'text-emerald-700 bg-emerald-50 border-emerald-200';
  if (['failed', 'error'].includes(normalized)) return 'text-red-700 bg-red-50 border-red-200';
  return 'text-panel-muted bg-panel-soft border-panel-line';
}

export function updatePrimaryAction(check?: Pick<UpdateCheck, 'update_available'>, status?: Pick<UpdateStatus, 'status'>): 'check' | 'update' {
  if (isUpdateInProgress(status?.status)) return 'update';
  return check?.update_available ? 'update' : 'check';
}

function rollbackSummary(status: UpdateStatus | undefined, text: (value: string) => string) {
  if (!status) return '-';
  if (status.rolled_back) {
    if (status.rollback_status === 'restored') return text('已回滚，服务已恢复');
    return text(`已回滚，状态 ${status.rollback_status || '未知'}`);
  }
  if (String(status.status || '').toLowerCase() === 'failed') return text('未确认回滚');
  return text('无回滚');
}

const translatableUpdateMessages = new Set([
  'idle',
  'update command accepted',
  'update command accepted in test mode',
  'update command completed; MiGate may restart if a new version was installed',
  'dev builds cannot be checked against releases',
  '正在执行更新任务，请等待状态刷新。',
  '上次更新状态长时间未完成，已标记为失败；可重新发起更新',
  '正在下载并校验升级包',
  '升级包校验完成，正在替换二进制和服务文件',
  '正在重启 MiGate 并执行健康检查',
  '升级成功，服务已恢复可用',
  '升级失败，已回滚，服务已恢复',
  '回滚失败，需要人工处理',
]);

const translatableCertificateOperationMessages = new Set([
  'preflight failed',
  'certificate issue started',
  'ACME issue failed',
  'issued certificate validation failed',
  'certificate issued',
  'certificate import failed',
  'write imported certificate failed',
  'certificate imported',
  'certificate apply failed',
  'certificate applied',
  'certificate deleted',
  'renew skipped',
  'renew failed',
  'certificate renewed',
]);

function certificateOperationMessageLabel(operation: Pick<CertificateOperation, 'message' | 'detail'>, text: (value: string) => string) {
  const message = String(operation.message || '').trim();
  if (message) return translatableCertificateOperationMessages.has(message) ? text(message) : message;
  return String(operation.detail || '').trim();
}

function updateStatusMessageLabel(message: string | undefined, text: (value: string) => string) {
  const value = String(message || '').trim();
  if (!value) return '';
  return translatableUpdateMessages.has(value) ? text(value) : value;
}

function serviceDetailLabel(detail: string | undefined, text: (value: string) => string) {
  const value = String(detail || '').trim();
  if (!value) return '';
  const match = value.match(/^启动于\s+(.+)$/);
  if (match) return `${text('启动于')} ${match[1]}`;
  return value;
}

export function updateStatusRefetchInterval(status?: string, watching = false) {
  return watching || isUpdateInProgress(status) ? 5000 : false;
}

export function updateDependencyRefetchInterval(watching = false) {
  return watching ? 5000 : false;
}

export function isUpdateInProgress(status?: string) {
  return ['pending', 'running', 'updating', 'downloading', 'installing', 'restarting'].includes(String(status || '').toLowerCase());
}

export function isUpdateTerminal(status?: string) {
  return ['started', 'failed', 'completed', 'idle'].includes(String(status || '').toLowerCase());
}

export function updateStatusSummaryKey(status?: Pick<UpdateStatus, 'status' | 'rolled_back' | 'rollback_status'>) {
  if (!status) return '';
  if (String(status.status).toLowerCase() === 'failed' && status.rolled_back && status.rollback_status === 'restored') {
    return '升级失败，已回滚，服务已恢复';
  }
  if (String(status.status).toLowerCase() === 'completed') {
    return '升级成功，服务已可用';
  }
  return '';
}

export function formatUpdateLogs(data: { logs?: string; lines?: string[] } | undefined, emptyMessage: string): string {
  if (!data) return emptyMessage;
  if (Array.isArray(data.lines)) return data.lines.join('\n');
  return data.logs || emptyMessage;
}
