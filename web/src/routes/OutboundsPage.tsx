import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, Edit2, Gauge, Plus, Power, RefreshCw, Rss, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import type { Outbound, OutboundSubscription, OutboundSubscriptionPreview, PingResult, ProxyPoolProxy } from '../api/types';
import { EmptyState, Field, FieldError, LoadingBlock, Modal, SpinnerButton, StatusBadge, toggleButtonClass, useConfirm, useToast } from '../components/ui';
import { coreLabel, outboundSupportedCores, outboundSupportLevel, outboundSupportLevelLabel } from '../lib/cores';
import { useI18n } from '../lib/i18n';
import { showCoreApplyWarning } from '../lib/coreApply';
import { refreshOutboundDependencies } from '../lib/queryInvalidation';
import { z } from '../lib/zod';
import { PageTitle } from './OverviewPage';

const schema = z.object({
  tag: z.string().min(1, '请输入 tag'),
  remark: z.string().optional(),
  protocol: z.enum(['socks', 'http', 'https', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'shadowtls', 'freedom', 'blackhole', 'dns']),
  address: z.string().optional(),
  port: z.coerce.number().min(0).max(65535).optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  enabled: z.boolean().default(true),
});
type InputValues = z.input<typeof schema>;
type Values = z.output<typeof schema>;
type ProxyPoolType = 'socks5' | 'http' | 'https';
const proxyPoolPageSize = 100;
export const defaultOutboundSubscriptionUpdateIntervalSeconds = 21600;
const subscriptionSchema = z.object({
  remark: z.string().optional(),
  url: z.string().min(1, '请输入订阅 URL'),
  tag_prefix: z.string().optional(),
  update_interval_seconds: z.coerce.number().min(60).max(86400).default(defaultOutboundSubscriptionUpdateIntervalSeconds),
  enabled: z.boolean().default(true),
  allow_private: z.boolean().default(false),
  prepend: z.boolean().default(false),
});
type SubscriptionInput = z.input<typeof subscriptionSchema>;
type SubscriptionValues = z.output<typeof subscriptionSchema>;

export default function OutboundsPage() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const { showToast } = useToast();
  const { text } = useI18n();
  const [editing, setEditing] = useState<Outbound | null>(null);
  const [editingSubscription, setEditingSubscription] = useState<OutboundSubscription | null>(null);
  const [poolOpen, setPoolOpen] = useState(false);
  const [latency, setLatency] = useState<Record<number, PingResult>>({});
  const [pingingIds, setPingingIds] = useState<Set<number>>(() => new Set());
  const outbounds = useQuery({ queryKey: ['outbounds'], queryFn: api.outbounds });
  const subscriptions = useQuery({ queryKey: ['outbound-subscriptions'], queryFn: api.outboundSubscriptions });
  const refresh = () => refreshOutboundDependencies(queryClient);
  const items = outbounds.data || [];
  const subscriptionItems = subscriptions.data || [];
  const subscriptionLookup = useMemo(() => buildSubscriptionLookup(subscriptionItems), [subscriptionItems]);
  const defaultItems = items.filter(isFixedDefaultOutbound);
  const customItems = items.filter((item) => !isFixedDefaultOutbound(item));
  const reorderableItems = customItems.filter(isReorderableOutbound);

  const toggle = useMutation({
    mutationFn: (item: Outbound) => api.toggleOutbound(item, !item.enabled),
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已保存，但核心配置未生效', showToast, text)) {
        showToast(text('出站状态已更新'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('出站状态更新失败')), 'error'),
  });
  const remove = useMutation({
    mutationFn: api.deleteOutbound,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已删除，但核心配置未生效', showToast, text)) {
        showToast(text('出站已删除'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('删除出站失败')), 'error'),
  });
  const ping = useMutation({
    mutationFn: api.pingOutbound,
    onSuccess: (result, id) => setLatency((prev) => ({ ...prev, [id]: result })),
    onError: (error) => showToast(errorMessage(error, text('测速失败')), 'error'),
  });
  const speedtest = useMutation({
    mutationFn: api.speedtestAll,
    onSuccess: (result) => {
      const mapped: Record<number, PingResult> = {};
      Object.entries(result).forEach(([id, value]) => {
        mapped[Number(id)] = value;
      });
      setLatency((prev) => ({ ...prev, ...mapped }));
      showToast(text('批量测速完成'), 'success');
    },
    onError: (error) => showToast(errorMessage(error, text('批量测速失败')), 'error'),
  });
  const reorder = useMutation({
    mutationFn: (ids: number[]) => api.reorderOutbounds(ids),
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已保存，但核心配置未生效', showToast, text)) {
        showToast(text('出站顺序已保存'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('保存顺序失败')), 'error'),
  });
  const refreshSub = useMutation({
    mutationFn: api.refreshOutboundSubscription,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '订阅已刷新，但核心配置未生效', showToast, text)) {
        showToast(text('出站订阅已刷新'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('刷新订阅失败')), 'error'),
  });
  const refreshSubAfterEnable = useMutation({
    mutationFn: api.refreshOutboundSubscription,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '订阅已刷新，但核心配置未生效', showToast, text)) {
        showToast(text('出站订阅已刷新'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('订阅已启用，请刷新以恢复节点')), 'error'),
  });
  const refreshSubscriptionAfterEnable = (id: number) => {
    refreshSubAfterEnable.mutate(id);
  };
  const refreshAllSubs = useMutation({
    mutationFn: api.refreshOutboundSubscriptions,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '订阅已刷新，但核心配置未生效', showToast, text)) {
        showToast(text('出站订阅已刷新'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('刷新订阅失败')), 'error'),
  });
  const removeSub = useMutation({
    mutationFn: api.deleteOutboundSubscription,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '订阅已删除，但核心配置未生效', showToast, text)) {
        showToast(text('出站订阅已删除'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('删除订阅失败')), 'error'),
  });
  const reorderSub = useMutation({
    mutationFn: api.reorderOutboundSubscriptions,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '订阅顺序已保存，但核心配置未生效', showToast, text)) {
        showToast(text('订阅顺序已保存'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('保存订阅顺序失败')), 'error'),
  });
  const pingOutbound = async (id: number) => {
    if (pingingIds.has(id)) return;
    setPingingIds((prev) => new Set(prev).add(id));
    try {
      await ping.mutateAsync(id);
    } catch {
      // The mutation's onError handler already shows the user-facing message.
    } finally {
      setPingingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  if (outbounds.isLoading) return <LoadingBlock />;
  return (
    <div className="page-stack">
      <PageTitle
        title={text('出站管理')}
        description={text('配置默认直连、阻断以及 SOCKS / HTTP 代理链路。')}
        action={
          <div className="flex flex-wrap gap-2">
            <button className="btn secondary" onClick={() => setPoolOpen(true)}>{text('导入代理池')}</button>
            <button className="btn secondary" onClick={() => setEditingSubscription(emptySubscription(subscriptions.data || []))}><Rss className="h-4 w-4" /> {text('出站订阅')}</button>
            <SpinnerButton className="btn secondary" loading={refreshAllSubs.isPending} onClick={() => refreshAllSubs.mutate()}><RefreshCw className="h-4 w-4" /> {text('刷新订阅')}</SpinnerButton>
            <SpinnerButton className="btn secondary" loading={speedtest.isPending} onClick={() => speedtest.mutate()}><Gauge className="h-4 w-4" /> {text('批量测速')}</SpinnerButton>
            <button className="btn primary" onClick={() => setEditing({ id: 0, tag: '', protocol: 'socks', enabled: true })}><Plus className="h-4 w-4" /> {text('新增出站')}</button>
          </div>
        }
      />
      {items.length === 0 ? <EmptyState title={text('暂无出站')} /> : null}
      <SubscriptionSection
        subscriptions={subscriptionItems}
        loading={subscriptions.isLoading}
        refreshingId={refreshSub.isPending ? refreshSub.variables : undefined}
        onAdd={() => setEditingSubscription(emptySubscription(subscriptionItems))}
        onEdit={setEditingSubscription}
        onRefresh={(id) => refreshSub.mutate(id)}
        onDelete={async (id) => (await confirm({ title: text('删除出站订阅？'), tone: 'danger' })) && removeSub.mutate(id)}
        onMove={(index, delta) => moveSubscription(subscriptionItems, index, delta, reorderSub.mutate)}
        text={text}
      />
      {defaultItems.length ? <h2 className="section-title">{text('默认出站')}</h2> : null}
      <div className="grid gap-3">
        {defaultItems.map((item, index) => (
          <div key={item.id} className="resource-card">
            <div className="resource-header">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-panel-soft px-2 py-1 text-xs">#{index + 1}</span>
                  <h2 className="truncate text-base font-semibold">{item.tag}</h2>
                  <StatusBadge enabled={item.enabled} />
                  <span className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{text('默认')}</span>
                  <CoreBadges item={item} text={text} />
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-panel-muted">
                  {outboundMetaParts(item, text).map((part) => <span key={part}>{part}</span>)}
                  <span>{formatLatency(latency[item.id], text)}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      {customItems.length ? <h2 className="section-title">{text('自定义出站')}</h2> : null}
      <div className="grid gap-3">
        {customItems.map((item, index) => (
          <div key={item.id} className="resource-card">
            <div className="resource-header">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-panel-soft px-2 py-1 text-xs">#{index + 1}</span>
                  <h2 className="truncate text-base font-semibold">{item.tag}</h2>
                  <OutboundProtocolBadge item={item} />
                  <SourceBadge item={item} subscription={subscriptionLookup.get(item.subscription_id || 0)} text={text} />
                  <CoreBadges item={item} text={text} />
                  <StatusBadge enabled={item.enabled} />
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-panel-muted">
                  {outboundMetaParts(item, text).slice(1).map((part) => <span key={part}>{part}</span>)}
                  <span>{formatLatency(latency[item.id], text)}</span>
                </div>
              </div>
              <div className="action-row">
                <button className="icon-button" disabled={!isReorderableOutbound(item) || reorderableItems.findIndex((o) => o.id === item.id) === 0} onClick={() => moveCustomOutbound(reorderableItems, reorderableItems.findIndex((o) => o.id === item.id), -1, reorder.mutate)} title={text('上移')}><ArrowUp className="h-4 w-4" /></button>
                <button className="icon-button" disabled={!isReorderableOutbound(item) || reorderableItems.findIndex((o) => o.id === item.id) === reorderableItems.length - 1} onClick={() => moveCustomOutbound(reorderableItems, reorderableItems.findIndex((o) => o.id === item.id), 1, reorder.mutate)} title={text('下移')}><ArrowDown className="h-4 w-4" /></button>
                <SpinnerButton className="icon-button" loading={pingingIds.has(item.id)} onClick={() => pingOutbound(item.id)} title="Ping"><Gauge className="h-4 w-4" /></SpinnerButton>
                <button className={toggleButtonClass(item.enabled)} disabled={outboundEnableDisabledReason(item, subscriptionLookup.get(item.subscription_id || 0), text) !== ''} onClick={() => toggle.mutate(item)} title={outboundToggleTitle(item, subscriptionLookup.get(item.subscription_id || 0), text)}><Power className="h-4 w-4" /></button>
                <button className="icon-button" onClick={() => setEditing(item)} title={text('编辑')}><Edit2 className="h-4 w-4" /></button>
                <button className="icon-button danger-text" disabled={item.source === 'subscription'} onClick={async () => (await confirm({ title: text('删除出站？'), tone: 'danger' })) && remove.mutate(item.id)} title={item.source === 'subscription' ? text('订阅节点不能单独删除') : text('删除')}><Trash2 className="h-4 w-4" /></button>
              </div>
            </div>
          </div>
        ))}
      </div>
      <OutboundModal outbound={editing} sourceSubscription={editing ? subscriptionLookup.get(editing.subscription_id || 0) : undefined} onClose={() => setEditing(null)} onSaved={refresh} />
      <SubscriptionModal subscription={editingSubscription} onClose={() => setEditingSubscription(null)} onSaved={refresh} onNeedsRefresh={refreshSubscriptionAfterEnable} />
      <ProxyPoolModal open={poolOpen} onClose={() => setPoolOpen(false)} onImported={() => { refresh(); setPoolOpen(false); }} />
    </div>
  );
}

function SubscriptionSection({ subscriptions, loading, refreshingId, onAdd, onEdit, onRefresh, onDelete, onMove, text }: {
  subscriptions: OutboundSubscription[];
  loading: boolean;
  refreshingId?: number;
  onAdd: () => void;
  onEdit: (sub: OutboundSubscription) => void;
  onRefresh: (id: number) => void;
  onDelete: (id: number) => void;
  onMove: (index: number, delta: number) => void;
  text: (value: string) => string;
}) {
  return (
    <section className="grid gap-3">
      <div className="flex items-center justify-between gap-3">
        <h2 className="section-title m-0">{text('出站订阅')}</h2>
        <button className="btn secondary" onClick={onAdd}><Plus className="h-4 w-4" /> {text('新增订阅')}</button>
      </div>
      {loading ? <LoadingBlock /> : null}
      {!loading && subscriptions.length === 0 ? <EmptyState title={text('暂无出站订阅')} /> : null}
      {subscriptions.map((sub, index) => (
        <div key={sub.id} className="resource-card">
          <div className="resource-header">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded bg-panel-soft px-2 py-1 text-xs">#{index + 1}</span>
                <h2 className="truncate text-base font-semibold">{sub.remark || sub.url}</h2>
                <StatusBadge enabled={sub.enabled} />
                <span className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{text('节点')}：{sub.outbound_count || 0}</span>
                {sub.prepend ? <span className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{text('置前')}</span> : null}
              </div>
              <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-panel-muted">
                {subscriptionMetaParts(sub, text).map((part) => <span key={part} className={part.startsWith(text('最近错误')) ? 'danger-text' : ''}>{part}</span>)}
              </div>
            </div>
            <div className="action-row">
              <button className="icon-button" disabled={index === 0} onClick={() => onMove(index, -1)} title={text('上移')}><ArrowUp className="h-4 w-4" /></button>
              <button className="icon-button" disabled={index === subscriptions.length - 1} onClick={() => onMove(index, 1)} title={text('下移')}><ArrowDown className="h-4 w-4" /></button>
              <SpinnerButton className="icon-button" loading={refreshingId === sub.id} onClick={() => onRefresh(sub.id)} title={text('刷新')}><RefreshCw className="h-4 w-4" /></SpinnerButton>
              <button className="icon-button" onClick={() => onEdit(sub)} title={text('编辑')}><Edit2 className="h-4 w-4" /></button>
              <button className="icon-button danger-text" onClick={() => onDelete(sub.id)} title={text('删除')}><Trash2 className="h-4 w-4" /></button>
            </div>
          </div>
        </div>
      ))}
    </section>
  );
}

function SubscriptionModal({ subscription, onClose, onSaved, onNeedsRefresh }: { subscription: OutboundSubscription | null; onClose: () => void; onSaved: () => void; onNeedsRefresh: (id: number) => void }) {
  const { showToast } = useToast();
  const { text } = useI18n();
  const form = useForm<SubscriptionInput, unknown, SubscriptionValues>({
    resolver: zodResolver(subscriptionSchema),
    defaultValues: subscriptionFormValues(null),
  });
  const [preview, setPreview] = useState<string>('');
  useEffect(() => {
    form.reset(subscriptionFormValues(subscription));
    setPreview('');
  }, [form, subscription]);
  const save = useMutation({
    mutationFn: (values: SubscriptionValues) => subscription?.id ? api.updateOutboundSubscription(subscription.id, values) : api.createOutboundSubscription(values),
    onSuccess: (response) => {
      if ('needs_refresh' in response && response.needs_refresh && response.subscription?.id) {
        showToast(text('订阅已启用，请刷新以恢复节点'), 'success');
        onNeedsRefresh(response.subscription.id);
      } else if (!showCoreApplyWarning(response, '已保存，但核心配置未生效', showToast, text)) {
        showToast(text('出站订阅已保存'), 'success');
      }
      onSaved();
      onClose();
    },
    onError: (error) => showToast(errorMessage(error, text('保存订阅失败')), 'error'),
  });
  const previewMutation = useMutation({
    mutationFn: (values: SubscriptionValues) => api.previewOutboundSubscription(values),
    onSuccess: (result) => setPreview(formatSubscriptionPreview(result, text)),
    onError: (error) => setPreview(errorMessage(error, text('预览失败'))),
  });
  return (
    <Modal open={!!subscription} title={text(subscription?.id ? '编辑出站订阅' : '新增出站订阅')} onClose={onClose} footer={<><button className="btn secondary" onClick={onClose}>{text('取消')}</button><SpinnerButton className="btn secondary" loading={previewMutation.isPending} onClick={form.handleSubmit((v) => previewMutation.mutate(v))}>{text('预览')}</SpinnerButton><SpinnerButton className="btn primary" loading={save.isPending} onClick={form.handleSubmit((v) => save.mutate(v))}>{text(subscription?.id ? '保存' : '添加')}</SpinnerButton></>}>
      <div className="form-grid">
        <Field label={text('备注')}><input {...form.register('remark')} /></Field>
        <Field label={text('订阅 URL')}><input {...form.register('url')} /><FieldError message={form.formState.errors.url?.message ? text(form.formState.errors.url.message) : undefined} /></Field>
        <Field label={text('标签前缀')}><input {...form.register('tag_prefix')} /></Field>
        <Field label={text('更新间隔（秒）')}><input type="number" {...form.register('update_interval_seconds')} /></Field>
        <label className="checkbox-field"><input type="checkbox" {...form.register('enabled')} /> {text('启用')}</label>
        <label className="checkbox-field"><input type="checkbox" {...form.register('allow_private')} /> {text('允许私有地址')}</label>
        <label className="checkbox-field span-2"><input type="checkbox" {...form.register('prepend')} /> {text('置于手动出站之前')}</label>
        {preview ? <div className="span-2 rounded bg-panel-soft px-3 py-2 text-xs text-panel-muted">{preview}</div> : null}
      </div>
    </Modal>
  );
}

function OutboundModal({ outbound, sourceSubscription, onClose, onSaved }: { outbound: Outbound | null; sourceSubscription?: OutboundSubscription; onClose: () => void; onSaved: () => void }) {
  const { showToast } = useToast();
  const { text } = useI18n();
  const form = useForm<InputValues, unknown, Values>({
    resolver: zodResolver(schema),
    defaultValues: outboundFormValues(null),
  });
  useEffect(() => {
    form.reset(outboundFormValues(outbound));
  }, [form, outbound]);
  const protocol = form.watch('protocol');
  const subscriptionManaged = outbound?.source === 'subscription';
  const subscriptionDisabledReason = outbound ? outboundEnableDisabledReason(outbound, sourceSubscription, text) : '';
  const supportLevel = outboundSupportLevel({ protocol });
  const supportedCores = outboundSupportedCores({ protocol });
  const credentialFields = outboundCredentialFields(protocol);
  const save = useMutation({
    mutationFn: (values: Values) => {
      const nextValues = subscriptionDisabledReason ? { ...values, enabled: false } : values;
      const payload = outbound && subscriptionManaged ? subscriptionOutboundUpdatePayload(outbound, nextValues) : outbound ? { ...outbound, ...sanitizeOutboundValues(nextValues) } : sanitizeOutboundValues(nextValues);
      delete (payload as Partial<Outbound>).supported_cores;
      return outbound?.id ? api.updateOutbound(outbound.id, payload) : api.createOutbound(payload);
    },
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已保存，但核心配置未生效', showToast, text)) {
        showToast(text('出站已保存'), 'success');
      }
      onSaved();
      onClose();
    },
    onError: (error) => showToast(errorMessage(error, text('保存出站失败')), 'error'),
  });
  return (
    <Modal open={!!outbound} title={text(outbound?.id ? '编辑出站' : '新增出站')} onClose={onClose} footer={<><button className="btn secondary" onClick={onClose}>{text('取消')}</button><SpinnerButton className="btn primary" loading={save.isPending} onClick={form.handleSubmit((v) => save.mutate(v))}>{text('保存')}</SpinnerButton></>}>
      <div className="form-grid">
        {subscriptionManaged ? <div className="span-2 rounded bg-panel-soft px-3 py-2 text-xs text-panel-muted">{text('该节点由出站订阅管理，仅允许修改启停和备注；下次刷新可能覆盖备注。')} {text('来源')}：{subscriptionSourceLabel(outbound, sourceSubscription, text)}{sourceSubscription?.enabled === false ? `，${text('订阅已停用')}` : ''}</div> : null}
        <Field label={text('标签')}><input disabled={subscriptionManaged} {...form.register('tag')} /><FieldError message={form.formState.errors.tag?.message ? text(form.formState.errors.tag.message) : undefined} /></Field>
        <Field label={text('备注')}><input {...form.register('remark')} /></Field>
        <Field label={text('协议')}>
          <select disabled={subscriptionManaged} {...form.register('protocol')}>
            <option value="socks">SOCKS5</option>
            <option value="http">HTTP</option>
            <option value="https">HTTPS</option>
            <option value="vless">VLESS</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
            <option value="hysteria2">Hysteria2</option>
            <option value="tuic">TUIC</option>
            <option value="shadowtls">ShadowTLS</option>
            <option value="freedom">freedom</option>
            <option value="blackhole">blackhole</option>
            <option value="dns">dns</option>
          </select>
        </Field>
        {supportLevel !== 'none' || supportedCores.length ? (
          <div className="span-2 flex flex-wrap items-center gap-2 text-xs text-panel-muted">
            {supportLevel !== 'none' ? <span className="rounded bg-panel-soft px-2 py-1">{text(outboundSupportLevelLabel(supportLevel))}</span> : null}
            {supportedCores.length ? <span>{text('可用于')}</span> : null}
            {supportedCores.map((core) => <span key={core} className="rounded bg-panel-soft px-2 py-1">{coreLabel(core)}</span>)}
          </div>
        ) : null}
        {supportLevel === 'basic' ? <div className="span-2 text-xs text-panel-muted">{text('仅保存基础连接参数，暂不包含传输层/TLS/REALITY 等高级字段。')}</div> : null}
        {requiresOutboundAddress(protocol) ? (
          <>
            <Field label={text('地址')}><input disabled={subscriptionManaged} {...form.register('address')} /></Field>
            <Field label={text('端口')}><input disabled={subscriptionManaged} type="number" {...form.register('port')} /></Field>
            {credentialFields.username ? <Field label={text(outboundUsernameLabel(protocol))}><input disabled={subscriptionManaged} {...form.register('username')} /></Field> : null}
            {credentialFields.password ? <Field label={text(outboundPasswordLabel(protocol))}><input disabled={subscriptionManaged} type="password" {...form.register('password')} /></Field> : null}
          </>
        ) : null}
        <label className="checkbox-field" title={subscriptionDisabledReason}><input type="checkbox" disabled={subscriptionDisabledReason !== ''} {...form.register('enabled')} /> {text('已启用')}</label>
      </div>
    </Modal>
  );
}

export function outboundFormValues(outbound: Outbound | null): InputValues {
  return outbound
    ? {
        tag: outbound.tag || '',
        remark: outbound.remark || '',
        protocol: (outbound.protocol || 'socks') as Values['protocol'],
        address: outbound.address || '',
        port: Number(outbound.port || 0),
        username: outbound.username || '',
        password: outbound.password || '',
        enabled: outbound.enabled ?? true,
      }
    : {
        tag: '',
        remark: '',
        protocol: 'socks',
        address: '',
        port: 0,
        username: '',
        password: '',
        enabled: true,
      };
}

export function emptySubscription(subscriptions: OutboundSubscription[]): OutboundSubscription {
  return {
    id: 0,
    remark: '',
    url: '',
    tag_prefix: `sub${subscriptions.length + 1}-`,
    update_interval_seconds: defaultOutboundSubscriptionUpdateIntervalSeconds,
    enabled: true,
    allow_private: false,
    prepend: false,
    priority: subscriptions.length,
  };
}

export function subscriptionFormValues(subscription: OutboundSubscription | null): SubscriptionInput {
  return subscription
    ? {
        remark: subscription.remark || '',
        url: subscription.url || '',
        tag_prefix: subscription.tag_prefix || '',
        update_interval_seconds: Number(subscription.update_interval_seconds || defaultOutboundSubscriptionUpdateIntervalSeconds),
        enabled: subscription.enabled ?? true,
        allow_private: subscription.allow_private ?? false,
        prepend: subscription.prepend ?? false,
      }
    : {
        remark: '',
        url: '',
        tag_prefix: 'sub1-',
        update_interval_seconds: defaultOutboundSubscriptionUpdateIntervalSeconds,
        enabled: true,
        allow_private: false,
        prepend: false,
      };
}

export function formatSubscriptionPreview(result: Pick<OutboundSubscriptionPreview, 'count' | 'skipped_count' | 'skipped'>, text: (value: string) => string): string {
  const skipped = Number(result.skipped_count || 0);
  const summary = `${text('成功解析')} ${result.count} ${text('个，跳过')} ${skipped} ${text('个')}`;
  if (!skipped) return summary;
  const details = (result.skipped || []).slice(0, 3).map((item) => `${item.protocol || text('未知协议')}：${item.reason}`).join('；');
  return details ? `${summary}。${details}` : summary;
}

export function subscriptionMetaParts(sub: Pick<OutboundSubscription, 'tag_prefix' | 'last_fetched_at' | 'last_attempt_at' | 'last_error'>, text: (value: string) => string): string[] {
  return [
    sub.tag_prefix || '-',
    `${text('上次成功拉取')}：${formatTime(sub.last_fetched_at, text)}`,
    `${text('上次尝试')}：${formatTime(sub.last_attempt_at, text)}`,
    sub.last_error ? `${text('最近错误')}：${sub.last_error}` : `${text('最近错误')}：-`,
  ];
}

export function subscriptionOutboundUpdatePayload(outbound: Outbound, values: Values): Outbound {
  return {
    ...outbound,
    remark: values.remark || outbound.remark || outbound.tag,
    enabled: values.enabled,
  };
}

export function movedSubscriptionIds(items: OutboundSubscription[], index: number, delta: number): number[] {
  const next = [...items];
  const target = index + delta;
  if (target < 0 || target >= next.length) return next.map((item) => item.id);
  [next[index], next[target]] = [next[target], next[index]];
  return next.map((item) => item.id);
}

function moveSubscription(items: OutboundSubscription[], index: number, delta: number, save: (ids: number[]) => void) {
  save(movedSubscriptionIds(items, index, delta));
}

function ProxyPoolModal({ open, onClose, onImported }: { open: boolean; onClose: () => void; onImported: () => void }) {
  const { showToast } = useToast();
  const { text } = useI18n();
  const [poolType, setPoolType] = useState<ProxyPoolType>('socks5');
  const [country, setCountry] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<ProxyPoolProxy | null>(null);
  const [latency, setLatency] = useState<Record<string, PingResult>>({});
  const poolSummary = useQuery({ queryKey: ['proxy-pool', poolType, 'summary'], queryFn: () => api.proxyPool(poolType, { summary: true }), enabled: open, staleTime: 60_000 });
  const pool = useQuery({ queryKey: ['proxy-pool', poolType, country, page, proxyPoolPageSize], queryFn: () => api.proxyPool(poolType, { country, page, per_page: proxyPoolPageSize }), enabled: open, staleTime: 60_000 });
  const regions = useMemo(() => [...(poolSummary.data?.regions || [])].sort((a, b) => b.count - a.count), [poolSummary.data]);
  const total = pool.data?.total || 0;
  const hasPrev = page > 1;
  const hasNext = page * proxyPoolPageSize < total;
  const ping = useMutation({
    mutationFn: (proxy: Pick<ProxyPoolProxy, 'address' | 'port'>) => api.pingProxyPool(poolType, proxy),
    onSuccess: (result, proxy) => setLatency((prev) => ({ ...prev, [proxyKey(proxy)]: result })),
  });
  const importProxy = useMutation({
    mutationFn: (proxy: ProxyPoolProxy) => api.importProxyPool(poolType, proxy),
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '已保存，但核心配置未生效', showToast, text)) {
        showToast(text('代理出站已导入'), 'success');
      }
      onImported();
    },
    onError: (error) => showToast(errorMessage(error, text('导入失败')), 'error'),
  });
  return (
    <Modal
      open={open}
      title={text('导入代理池')}
      onClose={onClose}
      panelClassName="socks5-pool-panel"
      footer={
        <>
          <button className="btn secondary" onClick={onClose}>{text('取消')}</button>
          <SpinnerButton className="btn primary" loading={importProxy.isPending} disabled={!selected} onClick={() => selected && importProxy.mutate(selected)}>{text('导入选中代理')}</SpinnerButton>
        </>
      }
    >
      <div className="socks5-pool-layout">
        <div className="grid content-start gap-3">
          <Field label={text('代理类型')}>
            <select
              id="proxy-pool-type"
              name="proxy_pool_type"
              value={poolType}
              onChange={(event) => {
                setPoolType(event.target.value as ProxyPoolType);
                setCountry('');
                setPage(1);
                setSelected(null);
                setLatency({});
              }}
            >
              <option value="socks5">SOCKS5</option>
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
            </select>
          </Field>
          <Field label={text('国家/地区')}>
            <select id="proxy-pool-country" name="proxy_pool_country" value={country} onChange={(event) => { setCountry(event.target.value); setPage(1); setSelected(null); }}>
              <option value="">{text('全部地区')}</option>
              {regions.map((region) => <option key={region.code} value={region.code}>{region.name || region.code} ({region.count})</option>)}
            </select>
          </Field>
          <div className="rounded-lg bg-panel-soft p-3 text-xs leading-6 text-panel-muted">
            <div>{text('缓存')}：{poolSummary.data?.cache_status || pool.data?.cache_status || '-'}</div>
            <div>{text('更新')}：{poolSummary.data?.cache_updated_at || pool.data?.cache_updated_at || '-'}</div>
            <div>{text('下次刷新')}：{poolSummary.data?.next_refresh_at || pool.data?.next_refresh_at || '-'}</div>
            <div>{text('代理数量')}：{total}</div>
          </div>
          {selected ? <div className="rounded-lg bg-panel-soft p-3 text-xs leading-6"><b>{selected.address}:{selected.port}</b><br />{selected.city || selected.country} {selected.asn} {selected.organization}</div> : null}
        </div>
        <div className="socks5-pool-list">
          {pool.isLoading ? <LoadingBlock /> : null}
          {(pool.data?.proxies || []).map((proxy) => {
            const key = proxyKey(proxy);
            return (
              <button key={key} className={`pool-row ${selected === proxy ? 'pool-row-active' : ''}`} onClick={() => setSelected(proxy)} type="button">
                <span className="pool-row-main">
                  <b className="pool-row-address">{proxy.address}:{proxy.port}</b>
                  <span className="pool-row-meta">{proxy.country || proxy.country_code} · {proxy.city || '-'} · {proxy.asn || '-'} · {proxy.organization || '-'}</span>
                </span>
                <span className="pool-row-actions">
                  <span className="pool-row-latency">{formatLatency(latency[key], text)}</span>
                  <span className="btn secondary h-8" onClick={(event) => { event.stopPropagation(); ping.mutate(proxy); }}>Ping</span>
                </span>
              </button>
            );
          })}
          {!pool.isLoading && total > proxyPoolPageSize ? (
            <div className="flex items-center justify-between gap-2 px-1 py-2 text-xs text-panel-muted">
              <button className="btn secondary h-8" disabled={!hasPrev} onClick={() => setPage((value) => Math.max(1, value - 1))}>{text('上一页')}</button>
              <span>{page} / {Math.max(1, Math.ceil(total / proxyPoolPageSize))}</span>
              <button className="btn secondary h-8" disabled={!hasNext} onClick={() => setPage((value) => value + 1)}>{text('下一页')}</button>
            </div>
          ) : null}
          {!pool.isLoading && (pool.data?.proxies || []).length === 0 ? <EmptyState title={text('暂无代理')} /> : null}
        </div>
      </div>
    </Modal>
  );
}

export function isFixedDefaultOutbound(item: Outbound) {
  return (item.tag === 'direct' && item.protocol === 'freedom') || (item.tag === 'blocked' && item.protocol === 'blackhole') || (item.tag === 'dns' && item.protocol === 'dns');
}

export function isReorderableOutbound(item: Outbound) {
  return item.source !== 'subscription' && item.protocol !== 'freedom' && item.protocol !== 'blackhole' && item.protocol !== 'dns';
}

function formatLatency(result: PingResult | undefined, text: (value: string) => string) {
  if (!result) return text('未测速');
  if (result.latency < 0) return result.error || text('不可达');
  return `${Number(result.latency).toFixed(0)} ms`;
}

export function customOutboundIds(items: Outbound[]): number[] {
  return items.filter(isReorderableOutbound).map((item) => item.id);
}

export function movedCustomOutboundIds(items: Outbound[], index: number, delta: number): number[] {
  const next = [...items];
  const target = index + delta;
  if (target < 0 || target >= next.length) return customOutboundIds(next);
  [next[index], next[target]] = [next[target], next[index]];
  return customOutboundIds(next);
}

function moveCustomOutbound(items: Outbound[], index: number, delta: number, save: (ids: number[]) => void) {
  save(movedCustomOutboundIds(items, index, delta));
}

function OutboundProtocolBadge({ item }: { item: Outbound }) {
  const type = outboundPoolType(item) || item.protocol || 'unknown';
  const label = type === 'socks5' ? 'SOCKS5' : type.toUpperCase();
  return <span className={`protocol-badge outbound-protocol-${type || 'default'}`}>{label}</span>;
}

function SourceBadge({ item, subscription, text }: { item: Outbound; subscription?: OutboundSubscription; text: (value: string) => string }) {
  if (item.source === 'subscription') {
    return (
      <>
        <span className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{subscriptionSourceLabel(item, subscription, text)}</span>
        {subscription?.enabled === false ? <span className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{text('订阅已停用')}</span> : null}
      </>
    );
  }
  if (item.source === 'proxy_pool' || outboundPoolType(item)) {
    return <span className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{text('代理池')}</span>;
  }
  return null;
}

export function buildSubscriptionLookup(subscriptions: OutboundSubscription[]): Map<number, OutboundSubscription> {
  return new Map(subscriptions.map((subscription) => [subscription.id, subscription]));
}

export function subscriptionDisplayName(subscription: Pick<OutboundSubscription, 'remark' | 'url'>): string {
  const remark = String(subscription.remark || '').trim();
  if (remark) return remark;
  const rawURL = String(subscription.url || '').trim();
  if (!rawURL) return '';
  try {
    const parsed = new URL(rawURL);
    return parsed.hostname || rawURL;
  } catch {
    return rawURL.replace(/^https?:\/\//, '').split(/[/?#]/, 1)[0] || rawURL;
  }
}

export function subscriptionSourceLabel(item: Pick<Outbound, 'source' | 'subscription_id'>, subscription: OutboundSubscription | undefined, text: (value: string) => string): string {
  if (item.source !== 'subscription') return '';
  if (!item.subscription_id || !subscription) return text('订阅已删除/未知');
  return `${text('订阅')}：${subscriptionDisplayName(subscription) || text('未命名')}`;
}

export function outboundEnableDisabledReason(item: Pick<Outbound, 'enabled' | 'source' | 'subscription_id'>, subscription: OutboundSubscription | undefined, text: (value: string) => string): string {
  if (item.enabled) return '';
  if (item.source === 'subscription' && item.subscription_id) {
    if (!subscription) return text('订阅已删除/未知');
    if (subscription.enabled === false) return text('所属订阅已停用');
  }
  return '';
}

export function outboundToggleTitle(item: Pick<Outbound, 'enabled' | 'source' | 'subscription_id'>, subscription: OutboundSubscription | undefined, text: (value: string) => string): string {
  return outboundEnableDisabledReason(item, subscription, text) || text('启停');
}

function CoreBadges({ item, text }: { item: Outbound; text: (value: string) => string }) {
  const cores = outboundSupportedCores(item);
  const level = outboundSupportLevel(item);
  if (level === 'none' && cores.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1 text-xs text-panel-muted">
      {level !== 'none' ? <span className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{text(outboundSupportLevelLabel(level))}</span> : null}
      {cores.length ? <span>{text('可用于')}</span> : null}
      {cores.map((core) => <span key={core} className="rounded bg-panel-soft px-2 py-1 text-xs text-panel-muted">{coreLabel(core)}</span>)}
    </div>
  );
}

function requiresOutboundAddress(protocol: string | undefined) {
  return !['freedom', 'blackhole', 'dns'].includes(String(protocol || '').trim().toLowerCase());
}

export function outboundUsernameLabel(protocol: string | undefined) {
  switch (String(protocol || '').trim().toLowerCase()) {
    case 'vless':
    case 'tuic':
      return 'UUID';
    case 'shadowsocks':
      return 'Shadowsocks 加密方法';
    default:
      return '用户名';
  }
}

export function outboundPasswordLabel(protocol: string | undefined) {
  switch (String(protocol || '').trim().toLowerCase()) {
    case 'shadowtls':
      return 'ShadowTLS 密码';
    default:
      return '密码';
  }
}

export function outboundCredentialFields(protocol: string | undefined) {
  switch (String(protocol || '').trim().toLowerCase()) {
    case 'vless':
      return { username: true, password: false };
    case 'trojan':
    case 'hysteria2':
    case 'shadowtls':
      return { username: false, password: true };
    case 'tuic':
    case 'shadowsocks':
    case 'socks':
    case 'socks5':
    case 'http':
    case 'https':
      return { username: true, password: true };
    default:
      return { username: false, password: false };
  }
}

export function sanitizeOutboundValues<T extends Pick<Values, 'protocol' | 'username' | 'password'> & Partial<Pick<Values, 'address' | 'port'>>>(values: T): T {
  const fields = outboundCredentialFields(values.protocol);
  const sanitized = {
    ...values,
    username: fields.username ? values.username : '',
    password: fields.password ? values.password : '',
  };
  if (!requiresOutboundAddress(values.protocol)) {
    sanitized.address = '';
    sanitized.port = 0;
  }
  return sanitized;
}

function proxyKey(proxy: Pick<ProxyPoolProxy, 'address' | 'port'>) {
  return `${proxy.address}:${proxy.port}`;
}

function outboundPoolType(item: Pick<Outbound, 'tag'>): ProxyPoolType | '' {
  if (item.tag.startsWith('pool-https-')) return 'https';
  if (item.tag.startsWith('pool-http-')) return 'http';
  if (item.tag.startsWith('pool-socks-')) return 'socks5';
  return '';
}

export function outboundRemarkLabel(remark: string, text: (value: string) => string) {
  if (remark === '直接连接' || remark === '阻断') return text(remark);
  return remark;
}

export function outboundMetaParts(item: Pick<Outbound, 'protocol' | 'address' | 'port' | 'remark'>, text: (value: string) => string, proxy?: Pick<ProxyPoolProxy, 'country' | 'country_code'>): string[] {
  const remark = item.remark ? outboundRemarkLabel(item.remark, text) : '';
  const country = proxyCountryLabel(proxy);
  const showCountry = country && (!remark || !remark.includes(country));
  return [
    item.protocol,
    item.address ? `${item.address}:${item.port || ''}` : '',
    showCountry ? `${text('国家/地区')}：${country}` : '',
    remark ? `${text('备注')}：${remark}` : '',
  ].filter(Boolean);
}

function proxyCountryLabel(proxy?: Pick<ProxyPoolProxy, 'country' | 'country_code'>) {
  return String(proxy?.country || proxy?.country_code || '').trim();
}

function formatTime(value: string | undefined, text: (value: string) => string) {
  if (!value) return text('从未');
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function errorMessage(error: unknown, fallback: string) {
  return getAPIErrorMessage(error, fallback);
}
