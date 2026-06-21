import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowDown, ArrowRight, ArrowUp, Boxes, Check, Edit2, Plus, Power, Search, Shield, Trash2, Users } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import type { Inbound, Outbound, RoutingRule } from '../api/types';
import { EmptyState, Field, LoadingBlock, Modal, SpinnerButton, StatusBadge, toggleButtonClass, useConfirm, useToast } from '../components/ui';
import { coreLabel, inboundCore, outboundSupportedCores, outboundSupportsCore } from '../lib/cores';
import { useI18n } from '../lib/i18n';
import { refreshTopologyDependencies } from '../lib/queryInvalidation';
import { generatedInboundTag } from '../lib/routing';
import { showCoreApplyWarning } from '../lib/coreApply';
import { z } from '../lib/zod';
import { PageTitle } from './OverviewPage';

const schema = z.object({
  inbound_id: z.coerce.number().optional(),
  inbound_tag: z.string().optional(),
  client_id: z.coerce.number().optional(),
  client_email: z.string().optional(),
  domain: z.string().optional(),
  ip: z.string().optional(),
  rule_set: z.string().optional(),
  protocol: z.string().optional(),
  outbound_tag: z.string().min(1, '请选择出站'),
  outbound_id: z.coerce.number().int().positive('请选择出站'),
  enabled: z.boolean().default(true),
});
type InputValues = z.input<typeof schema>;
type Values = z.output<typeof schema>;
type ProxyPoolType = 'socks5' | 'http' | 'https';
type ProxyCountry = { country?: string; country_code?: string };

export default function RoutingPage() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const { showToast } = useToast();
  const { text } = useI18n();
  const [editing, setEditing] = useState<RoutingRule | null>(null);
  const rules = useQuery({ queryKey: ['routing-rules'], queryFn: api.routingRules });
  const outbounds = useQuery({ queryKey: ['outbounds'], queryFn: api.outbounds });
  const inbounds = useQuery({ queryKey: ['inbounds'], queryFn: api.inbounds });
  const refresh = () => refreshTopologyDependencies(queryClient);
  const remove = useMutation({
    mutationFn: api.deleteRoutingRule,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '规则已删除，但核心配置未生效', showToast, text)) {
        showToast(text('路由规则已删除'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('删除路由规则失败')), 'error'),
  });
  const toggle = useMutation({
    mutationFn: (item: RoutingRule) => api.updateRoutingRule(item.id, routingPayload({ ...item, enabled: !item.enabled })),
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '规则已保存，但核心配置未生效', showToast, text)) {
        showToast(text('路由规则状态已更新'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('更新路由规则失败')), 'error'),
  });
  const reorder = useMutation({
    mutationFn: api.reorderRoutingRules,
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '规则已保存，但核心配置未生效', showToast, text)) {
        showToast(text('路由顺序已保存'), 'success');
      }
      refresh();
    },
    onError: (error) => showToast(errorMessage(error, text('保存顺序失败')), 'error'),
  });
  const items = rules.data || [];
  const createDraft = newRoutingRuleDraft(outbounds.data || []);
  if (rules.isLoading) return <LoadingBlock />;
  return (
    <div className="page-stack">
      <PageTitle title={text('路由规则')} description={text('按入站、客户端、域名、IP、规则集或协议选择出站链路。')} action={<button className="btn primary" disabled={!createDraft} onClick={() => createDraft && setEditing(createDraft)} title={createDraft ? text('新增路由') : text('请先创建出站')}><Plus className="h-4 w-4" /> {text('新增路由')}</button>} />
      {items.length === 0 ? <EmptyState title={text('暂无路由规则')} /> : null}
      <div className="grid gap-3">
        {items.map((item, index) => (
          <div key={item.id} className="resource-card">
            <div className="resource-header">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-panel-soft px-2 py-1 text-xs">#{index + 1}</span>
                  <h2 className="truncate text-base font-semibold">{ruleTitle(item, text, inbounds.data || [], outbounds.data || [])}</h2>
                  <StatusBadge enabled={item.enabled} />
                  {item.client_id && !findClientById(inbounds.data || [], item.client_id) ? <StatusBadge enabled={false}>{text('客户端已缺失')}</StatusBadge> : null}
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-panel-muted">
                  <span>{item.client_id ? text('客户端级规则：入站 / 客户端 -> 出站') : text('入站级规则：入站 -> 出站')}</span>
                  <span>{text('inbound')}: {readableInboundName(item, inbounds.data || [], text) || item.inbound_tag || text('全部')}</span>
                  <span>{text('client')}: {clientDisplay(item, inbounds.data || [], text)}</span>
                  <span>{text('domain')}: {item.domain || '-'}</span>
                  <span>{text('ip')}: {item.ip || '-'}</span>
                  <span>{text('rule_set')}: {item.rule_set || '-'}</span>
                  <span>{text('protocol')}: {item.protocol || '-'}</span>
                  <span>{text('outbound')}: {readableOutboundName(item, outbounds.data || [])}</span>
                </div>
              </div>
              <div className="action-row">
                <button className="icon-button" disabled={index === 0} onClick={() => moveRule(items, index, -1, reorder.mutate)} title={text('上移')}><ArrowUp className="h-4 w-4" /></button>
                <button className="icon-button" disabled={index === items.length - 1} onClick={() => moveRule(items, index, 1, reorder.mutate)} title={text('下移')}><ArrowDown className="h-4 w-4" /></button>
                <SpinnerButton className={toggleButtonClass(item.enabled)} loading={toggle.isPending} onClick={() => toggle.mutate(item)} title={text('启停')}><Power className="h-4 w-4" /></SpinnerButton>
                <button className="icon-button" onClick={() => setEditing(item)} title={text('编辑')}><Edit2 className="h-4 w-4" /></button>
                <button className="icon-button danger-text" onClick={async () => (await confirm({ title: text('删除路由规则？'), tone: 'danger' })) && remove.mutate(item.id)} title={text('删除')}><Trash2 className="h-4 w-4" /></button>
              </div>
            </div>
          </div>
        ))}
      </div>
      <RoutingModal
        rule={editing}
        outbounds={outbounds.data || []}
        inbounds={inbounds.data || []}
        onClose={() => setEditing(null)}
        onSaved={refresh}
      />
    </div>
  );
}

function RoutingModal({ rule, outbounds, inbounds, onClose, onSaved }: { rule: RoutingRule | null; outbounds: Outbound[]; inbounds: Inbound[]; onClose: () => void; onSaved: () => void }) {
  const { showToast } = useToast();
  const { text } = useI18n();
  const inboundOptions = useMemo(() => inboundSelectionOptions(inbounds), [inbounds]);
  const initialOutboundOptions = useMemo(() => outboundSelectionOptions(outbounds), [outbounds]);
  const form = useForm<InputValues, unknown, Values>({
    resolver: zodResolver(schema),
    values: rule
      ? {
          inbound_tag: rule.inbound_tag || '',
          inbound_id: rule.inbound_id || 0,
          client_id: rule.client_id || 0,
          client_email: rule.client_email || '',
          domain: rule.domain || '',
          ip: rule.ip || '',
          rule_set: rule.rule_set || '',
          protocol: rule.protocol || '',
          outbound_tag: rule.outbound_tag || initialOutboundOptions[0]?.tag || 'direct',
          outbound_id: rule.outbound_id || initialOutboundOptions[0]?.id || 0,
          enabled: rule.enabled ?? true,
        }
      : undefined,
  });
  const watchedInboundTag = form.watch('inbound_tag') || '';
  const watchedInboundID = Number(form.watch('inbound_id') || 0);
  const watchedClientID = Number(form.watch('client_id') || 0);
  const outboundOptions = useMemo(() => outboundSelectionOptions(outbounds, new Map(), inbounds, watchedInboundID, watchedInboundTag, watchedClientID), [outbounds, inbounds, watchedInboundID, watchedInboundTag, watchedClientID]);
  const watchedOutboundTag = form.watch('outbound_tag') || outboundOptions[0]?.tag || 'direct';
  const watchedOutboundID = Number(form.watch('outbound_id') || 0);
  const clientOptions = useMemo(() => clientSelectionOptions(inbounds, watchedInboundID, watchedInboundTag, rule || undefined), [inbounds, watchedInboundID, watchedInboundTag, rule]);
  const selectedInboundOption = inboundOptions.find((option) => inboundOptionMatches(option, watchedInboundID, watchedInboundTag));
  const selectedClientOption = clientOptions.find((option) => option.id === watchedClientID);
  const selectedOutboundOption = outboundOptions.find((option) => watchedOutboundID > 0 && option.id === watchedOutboundID);
  const save = useMutation({
    mutationFn: (values: Values) => {
      const payload = routingPayload(values);
      return rule?.id ? api.updateRoutingRule(rule.id, payload) : api.createRoutingRule(payload);
    },
    onSuccess: (response) => {
      if (!showCoreApplyWarning(response, '规则已保存，但核心配置未生效', showToast, text)) {
        showToast(text('路由规则已保存'), 'success');
      }
      onSaved();
      onClose();
    },
    onError: (error) => showToast(errorMessage(error, text('保存路由规则失败')), 'error'),
  });
  return (
    <Modal open={!!rule} title={text(rule?.id ? '编辑路由规则' : '新增路由规则')} onClose={onClose} panelClassName="routing-modal-panel" footer={<><button className="btn secondary" onClick={onClose}>{text('取消')}</button><SpinnerButton className="btn primary" loading={save.isPending} onClick={form.handleSubmit((v) => save.mutate(v))}>{text('保存')}</SpinnerButton></>}>
      <div className="routing-rule-builder">
        <RouteSummary
          inbound={selectedInboundOption?.title || watchedInboundTag || text('全部入站')}
          client={selectedClientOption?.title || text('不指定客户端')}
          outbound={selectedOutboundOption?.tag || watchedOutboundTag}
          clientLevel={watchedClientID > 0}
          enabled={form.watch('enabled') ?? true}
        />
        <div className="routing-picker-grid">
          <InboundPicker
            options={inboundOptions}
            value={watchedInboundID}
            fallbackTag={watchedInboundTag}
            onChange={(option) => {
              form.setValue('inbound_id', option.id, { shouldDirty: true });
              form.setValue('inbound_tag', option.value, { shouldDirty: true });
              form.setValue('client_id', 0, { shouldDirty: true });
              form.setValue('client_email', '', { shouldDirty: true });
            }}
          />
          <ClientPicker
            options={clientOptions}
            value={watchedClientID}
            missingLabel={selectedClientOption?.missing ? text('客户端已缺失') : ''}
            onChange={(option) => {
              if (option.id > 0) {
                form.setValue('inbound_id', option.inboundID || 0, { shouldDirty: true });
                form.setValue('inbound_tag', option.inboundTag || '', { shouldDirty: true });
              }
              form.setValue('client_id', option.id, { shouldDirty: true });
              form.setValue('client_email', option.email, { shouldDirty: true });
            }}
          />
          <OutboundPicker
            options={outboundOptions}
            value={watchedOutboundID}
            onChange={(option) => {
              if (option.disabled) return;
              form.setValue('outbound_tag', option.tag, { shouldDirty: true });
              form.setValue('outbound_id', option.id, { shouldDirty: true });
            }}
          />
        </div>
        <section className="routing-match-panel">
          <div className="routing-match-header">
            <div>
              <div className="routing-match-title">{text('匹配条件')}</div>
              <div className="routing-match-help">{text('留空时仅按来源入站和客户端匹配。')}</div>
            </div>
            <label className="checkbox-field routing-enabled-toggle"><input type="checkbox" {...form.register('enabled')} /> {text('已启用')}</label>
          </div>
          <div className="routing-match-grid">
            <Field label={text('域名匹配')} help={text('支持逗号或换行分隔多个值。')}>
              <textarea rows={3} placeholder={text('geosite:netflix 或 example.com')} {...form.register('domain')} />
            </Field>
            <Field label={text('IP 匹配')} help={text('支持 geoip:cn、CIDR、单 IP，逗号或换行分隔。')}>
              <textarea rows={3} placeholder="geoip:private, 8.8.8.8/32" {...form.register('ip')} />
            </Field>
            <Field label={text('协议匹配')}><input placeholder="dns, bittorrent" {...form.register('protocol')} /></Field>
            <Field label={text('规则集')} help={text('预留字段，当前会保存但不会写入 Xray 配置。')}>
              <input placeholder="geosite-category-ads-all" {...form.register('rule_set')} />
            </Field>
          </div>
        </section>
      </div>
    </Modal>
  );
}

function RouteSummary({ inbound, client, outbound, clientLevel, enabled }: { inbound: string; client: string; outbound: string; clientLevel: boolean; enabled: boolean }) {
  const { text } = useI18n();
  return (
    <div className="routing-path-summary">
      <div className="routing-path-step">
        <Shield className="h-4 w-4" />
        <span className="routing-path-label">{text('来源入站')}</span>
        <strong>{inbound}</strong>
      </div>
      <ArrowRight className="routing-path-arrow h-4 w-4" />
      <div className={clientLevel ? 'routing-path-step' : 'routing-path-step routing-path-muted'}>
        <Users className="h-4 w-4" />
        <span className="routing-path-label">{text('客户端')}</span>
        <strong>{client}</strong>
      </div>
      <ArrowRight className="routing-path-arrow h-4 w-4" />
      <div className="routing-path-step">
        <Boxes className="h-4 w-4" />
        <span className="routing-path-label">{text('目标出站')}</span>
        <strong>{outbound}</strong>
      </div>
      <StatusBadge enabled={enabled}>{text(enabled ? '启用' : '禁用')}</StatusBadge>
    </div>
  );
}

function InboundPicker({ options, value, fallbackTag, onChange }: { options: InboundOption[]; value: number; fallbackTag: string; onChange: (option: InboundOption) => void }) {
  const { text } = useI18n();
  const [query, setQuery] = useState('');
  const filtered = filterInboundOptions(options, query);
  return (
    <div className="choice-field routing-picker">
      <div className="choice-field-header">
        <div>
          <span className="choice-label">{text('来源入站 Tag')}</span>
          <span className="choice-help">{text('留空表示所有入站。')}</span>
        </div>
        <span className="choice-count">{text('入站')} {options.filter((item) => item.value).length}</span>
      </div>
      <div className="choice-search">
        <Search className="h-4 w-4" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={text('搜索入站、Tag、备注')} />
      </div>
      <div className="choice-list" role="radiogroup" aria-label={text('来源入站 Tag')}>
        {filtered.map((option) => (
          <button key={option.value || 'all'} type="button" className={inboundOptionMatches(option, value, fallbackTag) ? 'choice-row choice-row-active inbound-choice-row' : 'choice-row inbound-choice-row'} onClick={() => onChange(option)} role="radio" aria-checked={inboundOptionMatches(option, value, fallbackTag)}>
            <span className="choice-row-main">
              {option.subtitle ? <span className="choice-row-kicker">{option.subtitle}</span> : null}
              <span className="choice-row-title-line">
                <span className="choice-row-title">{option.title}</span>
                <span className="choice-type-badge">{text(option.typeLabel)}</span>
              </span>
              <span className="choice-row-meta-grid">
                {option.meta.map((item) => <ChoiceMetaItem key={`${option.value}-${item.label}`} item={item} text={text} />)}
              </span>
            </span>
            {inboundOptionMatches(option, value, fallbackTag) ? <Check className="h-4 w-4" /> : null}
          </button>
        ))}
      </div>
    </div>
  );
}

function ClientPicker({ options, value, missingLabel, onChange }: { options: ClientOption[]; value: number; missingLabel: string; onChange: (option: ClientOption) => void }) {
  const { text } = useI18n();
  const [query, setQuery] = useState('');
  const filtered = filterClientOptions(options, query);
  return (
    <div className="choice-field routing-picker">
      <div className="choice-field-header">
        <div>
          <span className="choice-label">{text('客户端')}</span>
          <span className="choice-help">{text('选择后生成客户端级规则：入站 / 客户端 -> 出站。')}</span>
        </div>
        <span className="choice-count">{missingLabel || `${text('客户端')} ${Math.max(options.length - 1, 0)}`}</span>
      </div>
      <div className="choice-search">
        <Search className="h-4 w-4" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={text('搜索客户端 email')} />
      </div>
      <div className="choice-list" role="radiogroup" aria-label={text('客户端')}>
        {filtered.map((option) => (
          <button key={option.id || 'inbound-level'} type="button" className={option.id === value ? 'choice-row choice-row-active' : 'choice-row'} onClick={() => onChange(option)} role="radio" aria-checked={option.id === value}>
            <span className="choice-row-main">
              <span className="choice-row-title-line">
                <span className="choice-row-title">{option.title}</span>
                <span className="choice-type-badge">{text(option.typeLabel)}</span>
              </span>
              {option.subtitle ? <span className="choice-row-sub">{option.subtitle}</span> : null}
              <span className="choice-row-meta-grid">
                {option.meta.map((item) => <ChoiceMetaItem key={`${option.id}-${item.label}`} item={item} text={text} />)}
              </span>
            </span>
            {option.id === value ? <Check className="h-4 w-4" /> : null}
          </button>
        ))}
      </div>
    </div>
  );
}

function OutboundPicker({ options, value, onChange }: { options: OutboundOption[]; value: number; onChange: (option: OutboundOption) => void }) {
  const { text } = useI18n();
  const [query, setQuery] = useState('');
  const filtered = filterOutboundOptions(options, query);
  return (
    <div className="choice-field routing-picker">
      <div className="choice-field-header">
        <div>
          <span className="choice-label">{text('目标出站')}</span>
          <span className="choice-help">{text('按 tag、备注或协议筛选。')}</span>
        </div>
        <span className="choice-count">{text('出站')} {options.length}</span>
      </div>
      <div className="choice-search">
        <Search className="h-4 w-4" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={text('搜索出站、Tag、协议')} />
      </div>
      <div className="choice-list" role="radiogroup" aria-label={text('目标出站')}>
        {filtered.map((option) => (
          <button key={`${option.id}-${option.tag}`} type="button" disabled={option.disabled} className={`${option.id === value ? 'choice-row choice-row-active outbound-choice-row' : 'choice-row outbound-choice-row'}${option.disabled ? ' opacity-50' : ''}`} onClick={() => onChange(option)} role="radio" aria-checked={option.id === value}>
            <span className="choice-row-main">
              <span className="choice-row-title-line">
                <span className="choice-row-title">{option.tag}</span>
                <span className={`protocol-badge choice-protocol-badge outbound-protocol-${option.protocolType || 'default'}`}>{option.protocolLabel}</span>
                {option.cores.map((core) => <span key={core} className="choice-type-badge">{coreLabel(core)}</span>)}
              </span>
              {option.remark ? <span className="choice-row-sub">{option.remark}</span> : null}
              <span className="choice-row-meta-grid">
                {option.meta.map((item) => <ChoiceMetaItem key={`${option.tag}-${item.label}`} item={item} text={text} />)}
              </span>
            </span>
            {option.id === value ? <Check className="h-4 w-4" /> : null}
          </button>
        ))}
      </div>
    </div>
  );
}

function moveRule(items: RoutingRule[], index: number, delta: number, save: (ids: number[]) => void) {
  save(movedRoutingRuleIds(items, index, delta));
}

export function newRoutingRuleDraft(outbounds: Outbound[]): RoutingRule | null {
  const outbound = outbounds.find((item) => Number(item.id || 0) > 0);
  if (!outbound) return null;
  return { id: 0, outbound_id: outbound.id, outbound_tag: outbound.tag, enabled: true };
}

export function routingPayload(values: Pick<RoutingRule, 'inbound_id' | 'inbound_tag' | 'client_id' | 'client_email' | 'domain' | 'ip' | 'rule_set' | 'protocol' | 'outbound_tag' | 'outbound_id' | 'enabled'>): Record<string, unknown> {
  return {
    inbound_id: Number(values.inbound_id || 0),
    inbound_tag: values.inbound_tag || '',
    client_id: Number(values.client_id || 0),
    client_email: values.client_email || '',
    domain: values.domain || '',
    ip: values.ip || '',
    rule_set: values.rule_set || '',
    protocol: values.protocol || '',
    outbound_id: Number(values.outbound_id || 0),
    outbound_tag: values.outbound_tag,
    enabled: values.enabled,
  };
}

export function movedRoutingRuleIds(items: RoutingRule[], index: number, delta: number): number[] {
  const next = [...items];
  const target = index + delta;
  if (target < 0 || target >= next.length) return next.map((item) => item.id);
  [next[index], next[target]] = [next[target], next[index]];
  return next.map((item) => item.id);
}

export { generatedInboundTag };

export function inboundTagOptions(inbounds: Inbound[]): string[] {
  const values = inboundSelectionOptions(inbounds).map((item) => item.value);
  return Array.from(new Set(values.filter(Boolean)));
}

type InboundOption = {
  id: number;
  value: string;
  aliases?: string[];
  title: string;
  subtitle?: string;
  typeLabel: string;
  meta: ChoiceMeta[];
  search: string;
};

type ClientOption = {
  id: number;
  email: string;
  title: string;
  subtitle?: string;
  typeLabel: string;
  missing?: boolean;
  inboundID?: number;
  inboundTag?: string;
  meta: ChoiceMeta[];
  search: string;
};

type OutboundOption = {
  id: number;
  tag: string;
  protocolType: string;
  protocolLabel: string;
  remark: string;
  meta: ChoiceMeta[];
  cores: ReturnType<typeof outboundSupportedCores>;
  disabled?: boolean;
  search: string;
};

type ChoiceMeta = {
  label: string;
  value: string;
  translateValue?: boolean;
};

function formatChoiceMetaValue(item: ChoiceMeta, text: (value: string) => string) {
  return item.translateValue ? text(item.value) : item.value;
}

function ChoiceMetaItem({ item, text }: { item: ChoiceMeta; text: (value: string) => string }) {
  return (
    <span>
      <b>{text(item.label)}</b>
      <span className="choice-meta-value">{formatChoiceMetaValue(item, text)}</span>
    </span>
  );
}

export function inboundSelectionOptions(inbounds: Inbound[]): InboundOption[] {
  const options: InboundOption[] = [
    {
      id: 0,
      value: '',
      title: '全部入站',
      typeLabel: '全部',
      meta: [{ label: '范围：', value: '不限制来源入站' }],
      search: '全部入站 all inbound',
    },
  ];
  inbounds.forEach((item) => {
    const generated = generatedInboundTag(item);
    const remark = String(item.remark || '').trim();
    const clientCount = (item.clients || []).length;
    options.push({
      id: item.id,
      value: generated,
      aliases: remark && remark !== generated ? [remark] : undefined,
      title: remark || generated,
      subtitle: remark ? generated : undefined,
      typeLabel: '入站',
      meta: [
        { label: '协议：', value: `${item.protocol || '-'} ${item.port ? `:${item.port}` : ''}`.trim() },
        { label: '内核：', value: coreLabel(inboundCore(item)) },
        { label: '传输：', value: `${item.network || 'tcp'} / ${item.security || 'none'}` },
        { label: '客户端：', value: String(clientCount) },
      ].filter(Boolean) as ChoiceMeta[],
      search: [generated, remark, item.protocol, inboundCore(item), item.port, item.network, item.security].filter(Boolean).join(' ').toLowerCase(),
    });
  });
  const seen = new Set<string>();
  return options.filter((item) => {
    if (seen.has(item.value)) return false;
    seen.add(item.value);
    return true;
  });
}

function inboundOptionMatches(option: InboundOption, inboundID: number, fallbackTag = '') {
  if (inboundID > 0) return option.id === inboundID;
  return option.value === fallbackTag || Boolean(fallbackTag && option.aliases?.includes(fallbackTag));
}

export function clientSelectionOptions(inbounds: Inbound[], inboundID: number, inboundTag = '', rule?: Pick<RoutingRule, 'client_id' | 'client_email' | 'inbound_id' | 'inbound_tag'>): ClientOption[] {
  const lookup = buildInboundLookup(inbounds);
  const selectedInbound = inboundID > 0 ? inbounds.find((inbound) => inbound.id === inboundID) : inboundTag ? lookup.get(inboundTag) : undefined;
  const sourceInbounds = selectedInbound ? [selectedInbound] : inbounds;
  const options: ClientOption[] = [
    {
      id: 0,
      email: '',
      title: '不指定客户端',
      typeLabel: '入站级',
      meta: [{ label: '规则：', value: '入站 -> 出站', translateValue: true }],
      search: '不指定客户端 inbound level all',
    },
  ];
  sourceInbounds.forEach((inbound) => {
    const inboundTagValue = generatedInboundTag(inbound);
    const inboundName = inbound.remark || inboundTagValue;
    (inbound.clients || []).forEach((client) => {
      const email = String(client.email || '').trim();
      options.push({
        id: client.id,
        email,
        title: email || `client-${client.id}`,
        typeLabel: '客户端级',
        inboundID: inbound.id,
        inboundTag: inboundTagValue,
        meta: [
          { label: '入站：', value: inboundName },
          { label: '状态：', value: client.enabled === false ? '禁用' : '启用', translateValue: true },
        ],
        search: [email, client.uuid, inbound.remark, inboundTagValue].filter(Boolean).join(' ').toLowerCase(),
      });
    });
  });
  const clientID = Number(rule?.client_id || 0);
  if (clientID > 0 && !options.some((option) => option.id === clientID)) {
    const email = String(rule?.client_email || '').trim();
    options.push({
      id: clientID,
      email,
      title: email || `client-${clientID}`,
      typeLabel: '客户端已缺失',
      missing: true,
      inboundID: Number(rule?.inbound_id || inboundID || 0),
      inboundTag,
      meta: [
        { label: '状态：', value: '客户端已缺失', translateValue: true },
        { label: '规则：', value: '核心配置生成时跳过', translateValue: true },
      ],
      search: [email, clientID, 'missing deleted'].join(' ').toLowerCase(),
    });
  }
  return options;
}

export function outboundSelectionOptions(outbounds: Outbound[], proxyLookup = new Map<string, ProxyCountry>(), inbounds: Inbound[] = [], inboundID = 0, inboundTag = '', clientID = 0): OutboundOption[] {
  const values = outbounds.length
    ? outbounds
    : [
        { id: 0, tag: 'direct', protocol: 'freedom', remark: '直接连接', enabled: true },
        { id: 0, tag: 'blocked', protocol: 'blackhole', remark: '阻断', enabled: true },
      ];
  const seen = new Set<string>();
  return values
    .filter((item) => {
      if (!item.tag || seen.has(item.tag)) return false;
      seen.add(item.tag);
      return true;
    })
    .map((item) => {
      const proxy = proxyLookup.get(outboundLookupKey(item));
      const country = proxyCountryLabel(proxy);
      const remark = item.remark || '';
      const rawProtocolType = outboundPoolType(item) || item.protocol || 'default';
      const protocolType = protocolSlug(rawProtocolType);
      const cores = outboundSupportedCores(item);
      const requiredCores = requiredRouteCores(inbounds, inboundID, inboundTag, clientID);
      const disabled = requiredCores.length > 0 && requiredCores.some((core) => !outboundSupportsCore(item, core));
      const meta = [
        item.address ? { label: '地址：', value: `${item.address}:${item.port || ''}` } : null,
        { label: '内核：', value: cores.map(coreLabel).join(' / ') || '-' },
        disabled ? { label: '状态：', value: '当前来源内核不支持', translateValue: true } : null,
        country && (!remark || !remark.includes(country)) ? { label: '国家/地区：', value: country } : null,
        item.enabled === false ? { label: '状态：', value: '禁用', translateValue: true } : null,
      ].filter(Boolean) as ChoiceMeta[];
      return {
        id: item.id,
        tag: item.tag,
        protocolType,
        protocolLabel: protocolLabel(rawProtocolType),
        remark,
        meta,
        cores,
        disabled,
        search: [item.tag, item.remark, item.protocol, rawProtocolType, protocolType, protocolLabel(rawProtocolType), cores.join(' '), item.address, item.port, country].filter(Boolean).join(' ').toLowerCase(),
      };
    });
}

function requiredRouteCores(inbounds: Inbound[], inboundID: number, inboundTag: string, clientID: number) {
  if (clientID > 0) {
    const found = findClientById(inbounds, clientID);
    return found ? [inboundCore(found.inbound)] : [];
  }
  const lookup = buildInboundLookup(inbounds);
  const selected = inboundID > 0 ? inbounds.find((inbound) => inbound.id === inboundID) : inboundTag ? lookup.get(inboundTag) : undefined;
  const sourceInbounds = selected ? [selected] : inboundTag ? [] : inbounds;
  return Array.from(new Set(sourceInbounds.map(inboundCore)));
}

function filterInboundOptions(options: InboundOption[], query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return options;
  return options.filter((item) => item.search.includes(needle));
}

function filterClientOptions(options: ClientOption[], query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return options;
  return options.filter((item) => item.search.includes(needle));
}

function filterOutboundOptions(options: OutboundOption[], query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return options;
  return options.filter((item) => item.search.includes(needle));
}

function buildInboundLookup(inbounds: Inbound[]) {
  const lookup = new Map<string, Inbound>();
  inbounds.forEach((inbound) => {
    const generated = generatedInboundTag(inbound);
    const remark = String(inbound.remark || '').trim();
    lookup.set(generated, inbound);
    if (remark) lookup.set(remark, inbound);
  });
  return lookup;
}

function findClientById(inbounds: Inbound[], clientID: number) {
  for (const inbound of inbounds) {
    const found = (inbound.clients || []).find((client) => client.id === clientID);
    if (found) return { inbound, client: found };
  }
  return undefined;
}

function clientDisplay(rule: RoutingRule, inbounds: Inbound[], text: (value: string) => string) {
  const clientID = Number(rule.client_id || 0);
  if (!clientID) return '-';
  const found = findClientById(inbounds, clientID);
  if (found) return found.client.email || `client-${clientID}`;
  return `${rule.client_email || `client-${clientID}`} (${text('客户端已缺失')})`;
}

function outboundPoolType(item: Pick<Outbound, 'tag'>): ProxyPoolType | '' {
  if (item.tag.startsWith('pool-https-')) return 'https';
  if (item.tag.startsWith('pool-http-')) return 'http';
  if (item.tag.startsWith('pool-socks-')) return 'socks5';
  return '';
}

function outboundLookupKey(item: Pick<Outbound, 'tag' | 'address' | 'port'>) {
  const type = outboundPoolType(item);
  if (!type || !item.address || !item.port) return '';
  return `${type}:${item.address}:${item.port}`;
}

function proxyCountryLabel(proxy?: ProxyCountry) {
  return String(proxy?.country || proxy?.country_code || '').trim();
}

function protocolLabel(protocol: string) {
  const value = protocol || 'default';
  const normalized = protocolSlug(value);
  if (normalized === 'socks5') return 'SOCKS5';
  if (normalized === 'default') return 'OUT';
  return value.toUpperCase();
}

function protocolSlug(protocol: string) {
  return String(protocol || 'default').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') || 'default';
}

function errorMessage(error: unknown, fallback: string) {
  return getAPIErrorMessage(error, fallback);
}

export function ruleTitle(rule: RoutingRule, text: (value: string) => string, inbounds: Inbound[] = [], outbounds: Outbound[] = []) {
  const inbound = readableInboundName(rule, inbounds, text);
  const outbound = readableOutboundName(rule, outbounds);
  if (Number(rule.client_id || 0) > 0) {
    return `${readableClientInboundName(rule, inbounds, text, inbound) || inbound} / ${readableClientName(rule, inbounds, text)} -> ${outbound}`;
  }
  return `${inbound || firstRoutingMatch(rule, text)} -> ${outbound}`;
}

function firstRoutingMatch(rule: RoutingRule, text: (value: string) => string) {
  if (rule.domain) return compactRuleValue(rule.domain);
  if (rule.ip) return compactRuleValue(rule.ip);
  if (rule.rule_set) return compactRuleValue(rule.rule_set);
  if (rule.protocol) return `${text('协议')}: ${compactRuleValue(rule.protocol)}`;
  return rule.inbound_tag ? `${text('入站')}: ${rule.inbound_tag}` : text('全部入站');
}

function readableInboundName(rule: RoutingRule, inbounds: Inbound[], text: (value: string) => string) {
  const inbound = findInboundForRule(inbounds, rule);
  if (inbound) return String(inbound.remark || generatedInboundTag(inbound)).trim() || text('未命名入站');
  if (!rule.inbound_tag) return '';
  return String(rule.inbound_tag).trim();
}

function readableClientName(rule: RoutingRule, inbounds: Inbound[], text: (value: string) => string) {
  const clientID = Number(rule.client_id || 0);
  if (!clientID) return '-';
  const found = findClientById(inbounds, clientID);
  return String(found?.client.email || rule.client_email || rule.client_label || `${text('客户端')} #${clientID}`).trim();
}

function readableClientInboundName(rule: RoutingRule, inbounds: Inbound[], text: (value: string) => string, fallback = '') {
  const clientID = Number(rule.client_id || 0);
  const found = clientID ? findClientById(inbounds, clientID) : undefined;
  if (!found) return fallback || text('全部入站');
  return String(found.inbound.remark || generatedInboundTag(found.inbound)).trim() || text('未命名入站');
}

function findInboundForRule(inbounds: Inbound[], rule: Pick<RoutingRule, 'inbound_id' | 'inbound_tag'>) {
  const inboundID = Number(rule.inbound_id || 0);
  if (inboundID > 0) return inbounds.find((item) => item.id === inboundID);
  return findInboundByTag(inbounds, rule.inbound_tag || '');
}

function findInboundByTag(inbounds: Inbound[], tag: string) {
  const normalized = String(tag || '').trim();
  return inbounds.find((item) => generatedInboundTag(item) === normalized || String(item.remark || '').trim() === normalized);
}

function readableOutboundName(rule: Pick<RoutingRule, 'outbound_id' | 'outbound_tag'>, outbounds: Outbound[]) {
  const outboundID = Number(rule.outbound_id || 0);
  if (outboundID > 0) {
    const outbound = outbounds.find((item) => item.id === outboundID);
    if (outbound) return outbound.tag;
  }
  return rule.outbound_tag;
}

function compactRuleValue(value: string) {
  const first = value.split(/[\n,]/).map((item) => item.trim()).find(Boolean) || value.trim();
  return first.length > 64 ? `${first.slice(0, 61)}...` : first;
}
