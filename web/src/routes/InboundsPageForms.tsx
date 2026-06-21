import { useMutation, useQuery } from '@tanstack/react-query';
import { ChevronDown, Copy, Link2, RotateCcw, ShieldCheck, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useForm } from 'react-hook-form';
import type { UseFormRegisterReturn } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { getAPIErrorMessage } from '../api/client';
import { api } from '../api/endpoints';
import type { Client, CreateClientResponse, CreateInboundResponse, Inbound } from '../api/types';
import { Field, FieldError, Modal, SpinnerButton, useConfirm, useToast } from '../components/ui';
import { copyToClipboard } from '../lib/clipboard';
import { useI18n } from '../lib/i18n';
import { coreApplyWarning, coreApplyWarningTone } from '../lib/coreApply';
import { z } from '../lib/zod';
import {
  allowedInboundNetworks,
  allowedInboundSecurities,
  applyInboundTemplate,
  buildClientPayload,
  buildFullInboundPayload,
  clientFormValues,
  defaultClientName,
  enabledInboundAdvancedFields,
  generatedClientCredentialValues,
  generatedProtocolCredential,
  hasAttachableSettingCert,
  inboundCredentialType,
  inboundFormValues,
  inboundProtocolOptions,
  inboundSecurities,
  inboundTemplateOptions,
  sanitizeInboundFormValues,
  shouldSyncInboundWSHost,
  supportsInboundShareLink,
} from './InboundsPage';
import type { InboundTemplateId } from './InboundsPage';

const inboundSchema = z.object({
  remark: z.string().min(1, '请输入名称'),
  protocol: z.enum(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria2', 'tuic', 'shadowtls']),
  port: z.preprocess((value) => (value === '' || value == null ? 0 : value), z.coerce.number().int().min(0).max(65535)),
  network: z.string().min(1),
  security: z.string().min(1),
  uuid: z.string().optional(),
  enabled: z.boolean().default(true),
  ws_path: z.string().optional(),
  ws_host: z.string().optional(),
  grpc_service_name: z.string().optional(),
  reality_dest: z.string().optional(),
  reality_server_names: z.string().optional(),
  reality_short_id: z.string().optional(),
  reality_private_key: z.string().optional(),
  reality_public_key: z.string().optional(),
  ss_method: z.string().optional(),
  tls_cert_file: z.string().optional(),
  tls_key_file: z.string().optional(),
  tls_sni: z.string().optional(),
  tls_fingerprint: z.string().optional(),
  tls_alpn: z.string().optional(),
  xhttp_path: z.string().optional(),
  xhttp_mode: z.string().optional(),
  hy2_up_mbps: z.coerce.number().int().min(0).optional(),
  hy2_down_mbps: z.coerce.number().int().min(0).optional(),
  hy2_obfs: z.string().optional(),
  hy2_obfs_password: z.string().optional(),
  hy2_mport: z.string().optional(),
  tuic_congestion_control: z.string().optional(),
  tuic_zero_rtt: z.boolean().default(false),
  shadowtls_version: z.coerce.number().int().min(0).optional(),
  shadowtls_password: z.string().optional(),
});

const clientSchema = z.object({
  email: z.string().min(1, '请输入客户端名称'),
  uuid: z.string().optional(),
  credential_id: z.string().optional(),
  password: z.string().optional(),
  enabled: z.boolean().default(true),
  traffic_limit_gb: z.coerce.number().min(0).optional(),
  expiry_mode: z.enum(['unlimited', '30d', '90d', 'custom']).default('unlimited'),
  expiry_date: z.string().optional(),
});

export type InboundInput = z.input<typeof inboundSchema>;
export type InboundValues = z.output<typeof inboundSchema>;
export type ClientInput = z.input<typeof clientSchema>;
export type ClientValues = z.output<typeof clientSchema>;
type TemplateSelectValue = InboundTemplateId | 'keep';

const tlsFingerprintOptions = ['chrome', 'firefox', 'safari', 'ios', 'android', 'randomized'];
const tlsAlpnOptions = [
  { value: '', label: '不指定' },
  { value: 'h2', label: 'h2' },
  { value: 'http/1.1', label: 'http/1.1' },
  { value: 'h2,http/1.1', label: 'h2,http/1.1' },
];
const xhttpModeOptions = ['stream-one', 'packet-up'];
const hy2ObfsOptions = [
  { value: '', label: '关闭' },
  { value: 'salamander', label: 'salamander' },
];
const tuicCongestionOptions = ['bbr', 'cubic', 'new_reno'];
const shadowsocksMethodOptions = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'];
const realityTargets = ['www.cloudflare.com', 'www.microsoft.com', 'www.apple.com', 'www.google.com'];
const templatePreviewBase: InboundValues = {
  remark: '',
  protocol: 'vless',
  port: 0,
  network: 'tcp',
  security: 'reality',
  uuid: '',
  enabled: true,
  tuic_zero_rtt: false,
};

export function InboundModal({ inbound, onClose, onSaved }: { inbound: Inbound | null; onClose: () => void; onSaved: () => void }) {
  const { showToast } = useToast();
  const confirm = useConfirm();
  const { text } = useI18n();
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [templateId, setTemplateId] = useState<TemplateSelectValue>('recommended');
  const [createClientWithNode, setCreateClientWithNode] = useState(true);
  const [credentialOpen, setCredentialOpen] = useState(false);
  const form = useForm<InboundInput, unknown, InboundValues>({
    resolver: zodResolver(inboundSchema),
    defaultValues: inbound ? inboundFormValues(inbound) : undefined,
  });
  const clientForm = useForm<ClientInput, unknown, ClientValues>({
    resolver: zodResolver(clientSchema),
    defaultValues: inbound ? clientFormValues(inbound) : undefined,
  });
  useEffect(() => {
    if (!inbound) return;
    form.reset(inboundFormValues(inbound));
    clientForm.reset(clientFormValues(inbound));
    setAdvancedOpen(false);
    setCredentialOpen(false);
    setCreateClientWithNode(!inbound.id);
    setTemplateId(inbound.id ? 'keep' : 'recommended');
  }, [inbound, form, clientForm]);
  const protocol = form.watch('protocol');
  const network = form.watch('network');
  const security = form.watch('security');
  const allowedNetworks = allowedInboundNetworks(protocol || 'vless');
  const allowedSecurities = allowedInboundSecurities(protocol || 'vless', network || '');
  const enabledAdvanced = enabledInboundAdvancedFields({ protocol, network, security });
  const portValue = form.watch('port');
  const portRegistration = form.register('port');
  const cert = useQuery({ queryKey: ['cert-status'], queryFn: api.certStatus, enabled: !!inbound && security === 'tls', retry: false, staleTime: 60_000 });
  const settingCert = cert.data;
  const canAttachSettingCert = hasAttachableSettingCert(settingCert);
  const selectedTemplate = useMemo(() => inboundTemplateOptions().find((template) => template.id === templateId), [templateId]);
  const resetInitialClientForProtocol = (nextProtocol: InboundValues['protocol']) => {
    const generated = generatedClientCredentials(nextProtocol);
    const currentName = clientForm.getValues('email') || defaultClientName(form.getValues('remark'));
    clientForm.setValue('email', currentName, { shouldDirty: true, shouldValidate: true });
    clientForm.setValue('uuid', generated.uuid, { shouldDirty: true, shouldValidate: true });
    clientForm.setValue('credential_id', generated.credential_id, { shouldDirty: true, shouldValidate: true });
    clientForm.setValue('password', generated.password, { shouldDirty: true, shouldValidate: true });
  };
  const regenerateCredential = () => {
    form.setValue('uuid', generatedProtocolCredential(protocol), { shouldDirty: true, shouldValidate: true });
  };
  const regenerateInitialClientCredential = () => {
    const generated = generatedClientCredentials(protocol);
    clientForm.setValue('uuid', generated.uuid, { shouldDirty: true, shouldValidate: true });
    clientForm.setValue('credential_id', generated.credential_id, { shouldDirty: true, shouldValidate: true });
    clientForm.setValue('password', generated.password, { shouldDirty: true, shouldValidate: true });
  };
  const regenerateRealityShortID = () => {
    form.setValue('reality_short_id', randomHex(4), { shouldDirty: true, shouldValidate: true });
  };
  const setSanitizedValues = (next: InboundValues) => {
    (Object.keys(next) as Array<keyof InboundValues>).forEach((key) => {
      form.setValue(key, next[key], { shouldDirty: true, shouldValidate: true });
    });
  };
  const applyTemplate = (id: Exclude<TemplateSelectValue, 'keep'>) => {
    setTemplateId(id);
    const previousProtocol = form.getValues('protocol');
    const next = applyInboundTemplate(form.getValues() as InboundValues, id);
    setSanitizedValues(next);
    if (!inbound?.id && next.protocol !== previousProtocol) resetInitialClientForProtocol(next.protocol);
  };
  const requestApplyTemplate = async (id: Exclude<TemplateSelectValue, 'keep'>) => {
    if (inbound?.id) {
      const accepted = await confirm({
        title: text('应用节点类型？'),
        description: text('会覆盖当前表单中的协议、传输、安全和相关高级字段，保存前仍可取消。'),
      });
      if (!accepted) return;
    }
    applyTemplate(id);
  };
  const attachSettingCert = () => {
    if (!canAttachSettingCert || !settingCert) return;
    const previousTLSSNI = form.getValues('tls_sni');
    form.setValue('tls_cert_file', settingCert.cert_path.trim(), { shouldDirty: true, shouldValidate: true });
    form.setValue('tls_key_file', settingCert.key_path.trim(), { shouldDirty: true, shouldValidate: true });
    const domain = settingCert.domain.trim();
    if (domain) {
      form.setValue('tls_sni', domain, { shouldDirty: true, shouldValidate: true });
      if (shouldSyncInboundWSHost(form.getValues('network') || '', form.getValues('ws_host'), previousTLSSNI)) {
        form.setValue('ws_host', domain, { shouldDirty: true, shouldValidate: true });
      }
    }
    showToast(text('已关联设置中的 TLS 证书'), 'success');
  };
  const clearTLSCert = () => {
    form.setValue('tls_cert_file', '', { shouldDirty: true, shouldValidate: true });
    form.setValue('tls_key_file', '', { shouldDirty: true, shouldValidate: true });
    showToast(text('TLS 证书路径已清空'), 'success');
  };
  const generateRealityKeys = async () => {
    try {
      const keypair = await api.generateRealityKeypair();
      form.setValue('reality_private_key', keypair.private_key, { shouldDirty: true, shouldValidate: true });
      form.setValue('reality_public_key', keypair.public_key, { shouldDirty: true, shouldValidate: true });
      showToast(text('REALITY 密钥已生成'), 'success');
    } catch (error) {
      showToast(errorMessage(error, text('生成 REALITY 密钥失败')), 'error');
    }
  };
  const applyRealityTarget = (serverName: string) => {
    form.setValue('reality_dest', `${serverName}:443`, { shouldDirty: true, shouldValidate: true });
    form.setValue('reality_server_names', serverName, { shouldDirty: true, shouldValidate: true });
  };
  const clearRealitySettings = () => {
    form.setValue('reality_dest', '', { shouldDirty: true, shouldValidate: true });
    form.setValue('reality_server_names', '', { shouldDirty: true, shouldValidate: true });
    form.setValue('reality_short_id', '', { shouldDirty: true, shouldValidate: true });
    form.setValue('reality_private_key', '', { shouldDirty: true, shouldValidate: true });
    form.setValue('reality_public_key', '', { shouldDirty: true, shouldValidate: true });
  };
  const save = useMutation({
    mutationFn: ({ values, clientValues }: { values: InboundValues; clientValues?: ClientValues }) => {
      const initialClient = !inbound?.id && createClientWithNode && clientValues ? buildClientPayload(clientValues, values.protocol) : null;
      return inbound?.id ? api.updateInbound(inbound.id, buildFullInboundPayload(inbound, values)) : api.createInbound(buildFullInboundPayload(inbound, values, initialClient));
    },
    onSuccess: (response) => {
      const warning = coreApplyWarning(response, '节点已保存，但核心配置未生效');
      showToast(text(warning || '节点已保存'), warning ? coreApplyWarningTone(response) : 'success');
      onSaved();
      onClose();
    },
    onError: (error) => showToast(errorMessage(error, text('保存节点失败')), 'error'),
  });
  const submitInbound = form.handleSubmit((values) => {
    if (!inbound?.id && createClientWithNode) {
      void clientForm.handleSubmit((clientValues) => save.mutate({ values, clientValues }))();
      return;
    }
    save.mutate({ values });
  });
  const close = () => {
    onClose();
  };
  const currentProtocolSummary = `${protocol || '-'} / ${network || '-'} / ${security || '-'}`;
  const isAutoPort = Number(portValue || 0) === 0;
  const tlsCertSummary = form.watch('tls_cert_file') && form.watch('tls_key_file')
    ? `${form.watch('tls_cert_file')} / ${form.watch('tls_key_file')}`
    : text('未指定证书路径');
  const initialClientCredentialSummary = clientCredentialSummary(clientForm.watch() as ClientValues, inboundCredentialType(protocol), text);
  const templateOptions = useMemo(() => {
    return inboundTemplateOptions().map((template) => {
      const preview = applyInboundTemplate(templatePreviewBase, template.id);
      return { ...template, previewProtocol: preview.protocol };
    });
  }, []);
  return (
    <Modal
      open={!!inbound}
      title={text(inbound?.id ? '编辑节点' : '新增节点')}
      onClose={close}
      panelClassName="inbound-modal-panel"
      footer={
        <>
          <button className="btn secondary" onClick={close}>{text('取消')}</button>
          <SpinnerButton className="btn primary" loading={save.isPending} onClick={submitInbound}>{text('保存')}</SpinnerButton>
        </>
      }
    >
      <div className="inbound-config-shell">
        <aside className="template-panel inbound-config-sidebar">
          <div className="form-section-heading">
            <div>
              <div className="form-section-kicker">{text('节点类型')}</div>
              <h3>{text('选择一个可用方案')}</h3>
            </div>
          </div>
          <div className="current-combo-card">
            <span>{text('当前组合')}</span>
            <strong>{currentProtocolSummary}</strong>
            <small>{selectedTemplate ? text(selectedTemplate.label) : text('保留当前配置')}</small>
          </div>
          <div className="node-type-grid">
            {templateOptions.map((template) => {
              const { name, combo } = templateDisplayParts(template.label);
              const isLocalProxy = template.id.startsWith('local-');
              const shareable = !isLocalProxy && supportsInboundShareLink(template.previewProtocol);
              return (
                <button
                  key={template.id}
                  type="button"
                  className={templateId === template.id ? 'node-type-card active' : 'node-type-card'}
                  onClick={() => requestApplyTemplate(template.id)}
                >
                  <span>{text(name)}</span>
                  {combo ? <strong>{text(combo)}</strong> : null}
                  <small>{text(template.description || '')}</small>
                  <em>{text(isLocalProxy ? '本地代理' : shareable ? '支持节点链接' : '不生成节点链接')}</em>
                </button>
              );
            })}
          </div>
        </aside>
        <div className="inbound-config-main">
          <div className="inbound-main-columns">
            <div className="inbound-primary-stack">
              <section className="inbound-config-section connection-config-section">
                <div className="form-section-heading">
                  <div>
                    <div className="form-section-kicker">{text('连接信息')}</div>
                    <h3>{text('先创建一个可用节点')}</h3>
                  </div>
                  <div className="form-section-summary">{text(isAutoPort ? '端口自动分配' : `端口 ${portValue}`)}</div>
                </div>
                <div className="form-grid inbound-basic-grid">
                  <Field label={text('名称')}>
                    <input {...form.register('remark')} />
                    <FieldError message={form.formState.errors.remark?.message ? text(form.formState.errors.remark.message) : undefined} />
                  </Field>
                  <Field label={text('端口')} help={text('留空自动分配')}>
                    <div className={isAutoPort ? 'auto-port-control active' : 'auto-port-control'}>
                      <input
                        type="number"
                        placeholder={text('自动分配')}
                        name={portRegistration.name}
                        ref={portRegistration.ref}
                        onBlur={portRegistration.onBlur}
                        value={isAutoPort ? '' : String(portValue)}
                        onChange={(event) => {
                          const raw = event.target.value;
                          if (raw === '') {
                            form.setValue('port', 0, { shouldDirty: true, shouldValidate: true });
                            return;
                          }
                          const next = Number(raw);
                          if (!Number.isFinite(next)) return;
                          form.setValue('port', next, { shouldDirty: true, shouldValidate: true });
                        }}
                      />
                      <span>{text(isAutoPort ? '自动' : '手动')}</span>
                    </div>
                    <FieldError message={form.formState.errors.port?.message} />
                  </Field>
                  {enabledAdvanced.has('tls_sni') ? (
                    <Field label={text(protocol === 'shadowtls' ? '握手服务器' : '域名 / SNI')} help={protocol === 'shadowtls' ? text('握手端口固定为 443') : undefined}>
                      <input {...form.register('tls_sni')} placeholder="example.com" />
                    </Field>
                  ) : null}
                </div>
              </section>
              {!inbound?.id ? (
                <section className="inbound-config-section client-config-section">
                  <div className="form-section-heading">
                    <div>
                      <div className="form-section-kicker">{text('首个客户端')}</div>
                      <h3>{text('保存后即可连接')}</h3>
                    </div>
                    <div className="form-section-summary">{text(createClientWithNode ? '将同时创建' : '仅创建节点')}</div>
                  </div>
                  <div className={createClientWithNode ? 'client-create-card active' : 'client-create-card'}>
                    <div>
                      <strong>{text('同时创建客户端')}</strong>
                      <span>{text(createClientWithNode ? '生成首个客户端，之后可在节点卡片复制链接或二维码。' : '之后可在节点卡片中手动新增客户端。')}</span>
                    </div>
                    <label className="switch-field">
                      <input type="checkbox" checked={createClientWithNode} onChange={(event) => setCreateClientWithNode(event.target.checked)} />
                      <span>{text(createClientWithNode ? '开启' : '关闭')}</span>
                    </label>
                  </div>
                  {createClientWithNode ? (
                    <>
                      <div className="form-grid inbound-client-grid">
                        <Field label={text('客户端名称')}>
                          <input {...clientForm.register('email')} placeholder={text('例如：我的手机')} />
                          <FieldError message={clientForm.formState.errors.email?.message ? text(clientForm.formState.errors.email.message) : undefined} />
                        </Field>
                        <Field label={text('流量限额（GB，0 不限制）')}><input type="number" step="0.1" {...clientForm.register('traffic_limit_gb')} /></Field>
                        <Field label={text('到期时间')}>
                          <select {...clientForm.register('expiry_mode')}>
                            <option value="unlimited">{text('不限制')}</option>
                            <option value="30d">{text('30 天')}</option>
                            <option value="90d">{text('90 天')}</option>
                            <option value="custom">{text('自定义日期')}</option>
                          </select>
                        </Field>
                        {clientForm.watch('expiry_mode') === 'custom' ? <Field label={text('自定义到期日期')}><input type="date" {...clientForm.register('expiry_date')} /></Field> : null}
                        <Field label={text('状态')}>
                          <SwitchField checked={clientForm.watch('enabled') ?? true} inputProps={clientForm.register('enabled')} text={text} />
                        </Field>
                      </div>
                      <div className="credential-summary-panel">
                        <div>
                          <strong>{text('客户端凭据')}</strong>
                          <span>{initialClientCredentialSummary}</span>
                        </div>
                        <button className="advanced-toggle compact" type="button" onClick={() => setCredentialOpen((open) => !open)} aria-expanded={credentialOpen}>
                          <ChevronDown className={credentialOpen ? 'h-4 w-4 rotate-180' : 'h-4 w-4'} />
                          {text('客户端凭据')} · {text(credentialOpen ? '收起' : '展开')}
                        </button>
                      </div>
                      {credentialOpen ? (
                        <div className="advanced-panel credential-fields-panel">
                          <CredentialFields credentialType={inboundCredentialType(protocol)} form={clientForm} regenerateCredential={regenerateInitialClientCredential} text={text} regenerateLabel="重新生成客户端凭据" />
                        </div>
                      ) : null}
                    </>
                  ) : null}
                </section>
              ) : null}
            </div>
            <div className="inbound-secondary-stack">
              {security === 'reality' ? (
                <section className="inbound-config-section security-config-panel">
                  <div className="form-section-heading">
                    <div>
                      <div className="form-section-kicker">{text('安全配置')}</div>
                      <h3>{text('REALITY 伪装')}</h3>
                    </div>
                    <ShieldCheck className="section-icon" />
                  </div>
                  <div className="form-grid inbound-security-grid">
                    <Field label={text('伪装目标')}><input {...form.register('reality_dest')} placeholder="www.cloudflare.com:443" /></Field>
                    <Field label={text('服务名')}><input {...form.register('reality_server_names')} placeholder="www.cloudflare.com" /></Field>
                  </div>
                  <div className="quick-action-panel">
                    <div className="quick-action-title">{text('常用目标')}</div>
                    <div className="quick-target-grid">
                      {realityTargets.map((target) => (
                        <button key={target} className="btn secondary h-8" type="button" onClick={() => applyRealityTarget(target)}>
                          {target}
                        </button>
                      ))}
                    </div>
                    <div className="quick-tool-grid">
                      <button className="btn secondary h-8" type="button" onClick={generateRealityKeys}>
                        <RotateCcw className="h-4 w-4" /> {text('生成 X25519')}
                      </button>
                      <button className="btn secondary h-8" type="button" onClick={regenerateRealityShortID}>
                        <RotateCcw className="h-4 w-4" /> {text('生成 Short ID')}
                      </button>
                      <button className="btn secondary h-8" type="button" onClick={clearRealitySettings}>
                        <X className="h-4 w-4" /> {text('清空')}
                      </button>
                    </div>
                  </div>
                </section>
              ) : null}
              {security === 'tls' ? (
                <section className="inbound-config-section security-config-panel">
                  <div className="form-section-heading">
                    <div>
                      <div className="form-section-kicker">{text('安全配置')}</div>
                      <h3>{text('TLS 证书')}</h3>
                    </div>
                    <ShieldCheck className="section-icon" />
                  </div>
                  <div className="tls-cert-panel">
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-panel-text">{text('当前证书路径')}</div>
                      <div className="mt-1 break-all text-xs leading-5 text-panel-muted">{tlsCertSummary}</div>
                    </div>
                    <div className="action-row">
                      <button type="button" className="btn secondary h-8" disabled={!canAttachSettingCert} onClick={attachSettingCert}>
                        <Link2 className="h-4 w-4" /> {text('使用设置页证书')}
                      </button>
                      <button type="button" className="btn secondary h-8" onClick={clearTLSCert}>
                        <X className="h-4 w-4" /> {text('清空')}
                      </button>
                    </div>
                  </div>
                </section>
              ) : null}
            </div>
          </div>
          <section className="inbound-config-section inbound-advanced-section">
          <button className="advanced-toggle advanced-section-toggle" type="button" onClick={() => setAdvancedOpen((open) => !open)} aria-expanded={advancedOpen}>
            <ChevronDown className={advancedOpen ? 'h-4 w-4 rotate-180' : 'h-4 w-4'} />
            {text('高级设置')}
            <span>{text('协议、传输、内部标识和专家项')}</span>
          </button>
        {advancedOpen ? (
          <div className="advanced-panel inbound-advanced-panel">
            <div className="advanced-group">
              <div className="advanced-group-title">{text('协议与传输')}</div>
              <div className="form-grid advanced-form-grid">
                <Field label={text('协议')}>
                  <select
                    value={protocol}
                    onChange={(event) => {
                      setTemplateId('keep');
                      const previousProtocol = form.getValues('protocol');
                      const nextProtocol = event.target.value as InboundValues['protocol'];
                      setSanitizedValues(sanitizeInboundFormValues(form.getValues() as InboundValues, { protocol: nextProtocol }));
                      if (!inbound?.id && nextProtocol !== previousProtocol) resetInitialClientForProtocol(nextProtocol);
                    }}
                  >
                    {inboundProtocolOptions().map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </Field>
                <Field label={text('传输')}>
                  <select
                    value={network}
                    onChange={(event) => {
                      setTemplateId('keep');
                      setSanitizedValues(sanitizeInboundFormValues(form.getValues() as InboundValues, { network: event.target.value }));
                    }}
                  >
                    {allowedNetworks.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </Field>
                <Field label={text('安全')}>
                  <select
                    value={security}
                    onChange={(event) => {
                      setTemplateId('keep');
                      setSanitizedValues(sanitizeInboundFormValues(form.getValues() as InboundValues, { security: event.target.value }));
                    }}
                  >
                    {inboundSecurities.filter((p) => allowedSecurities.includes(p)).map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </Field>
              </div>
            </div>
            <div className="advanced-group">
              <div className="advanced-group-title">{text('内部标识')}</div>
              <div className="form-grid advanced-form-grid">
                <Field label={text('入站内部 ID')}>
                <div className="input-action-row">
                  <input {...form.register('uuid')} />
                  <button className="icon-button" type="button" onClick={regenerateCredential} title={text('重新生成内部 ID')}>
                    <RotateCcw className="h-4 w-4" />
                  </button>
                </div>
              </Field>
              {enabledAdvanced.has('reality_short_id') ? (
                <Field label={text('REALITY Short ID')}>
                  <div className="input-action-row">
                    <input {...form.register('reality_short_id')} />
                    <button className="icon-button" type="button" onClick={regenerateRealityShortID} title={text('重新生成 Short ID')}>
                      <RotateCcw className="h-4 w-4" />
                    </button>
                  </div>
                </Field>
              ) : null}
                <div className="advanced-note span-2">{text('仅用于识别这个入站，不是客户端连接凭据；一般无需修改。')}</div>
              </div>
            </div>
            {(enabledAdvanced.has('ws_path') || enabledAdvanced.has('grpc_service_name') || enabledAdvanced.has('xhttp_path') || enabledAdvanced.has('ws_host') || enabledAdvanced.has('xhttp_mode')) ? (
              <div className="advanced-group">
                <div className="advanced-group-title">{text('传输路径')}</div>
                <div className="form-grid advanced-form-grid">
                  {enabledAdvanced.has('ws_path') ? <Field label={text('WS/H2 路径')}><input {...form.register('ws_path')} /></Field> : null}
                  {enabledAdvanced.has('grpc_service_name') ? <Field label={text('gRPC 服务名')}><input {...form.register('grpc_service_name')} /></Field> : null}
                  {enabledAdvanced.has('xhttp_path') ? <Field label={text('XHTTP 路径')}><input {...form.register('xhttp_path')} /></Field> : null}
                  {enabledAdvanced.has('ws_host') ? <Field label={text('WS/H2 主机')}><input {...form.register('ws_host')} /></Field> : null}
                  {enabledAdvanced.has('xhttp_mode') ? <Field label={text('XHTTP 模式')}><SelectField formRegister={form.register('xhttp_mode')} options={xhttpModeOptions.map((value) => ({ value, label: value }))} /></Field> : null}
                </div>
              </div>
            ) : null}
            {(security === 'reality' || security === 'tls') ? (
              <div className="advanced-group">
                <div className="advanced-group-title">{text('TLS / REALITY 专家项')}</div>
                <div className="form-grid advanced-form-grid">
                  {security === 'reality' ? (
                    <>
                      <Field label={text('REALITY 私钥')}>
                        <div className="input-action-row">
                          <input {...form.register('reality_private_key')} />
                          <button className="icon-button" type="button" onClick={generateRealityKeys} title={text('生成 X25519 密钥')}>
                            <RotateCcw className="h-4 w-4" />
                          </button>
                        </div>
                      </Field>
                      <Field label={text('REALITY 公钥')}><input {...form.register('reality_public_key')} readOnly /></Field>
                      <Field label="TLS Fingerprint"><SelectField formRegister={form.register('tls_fingerprint')} options={tlsFingerprintOptions.map((value) => ({ value, label: value }))} /></Field>
                    </>
                  ) : null}
                  {security === 'tls' ? (
                    <>
                      {enabledAdvanced.has('tls_cert_file') ? <Field label={text('TLS 证书文件')}><input {...form.register('tls_cert_file')} /></Field> : null}
                      {enabledAdvanced.has('tls_key_file') ? <Field label={text('TLS 私钥文件')}><input {...form.register('tls_key_file')} /></Field> : null}
                      {enabledAdvanced.has('tls_fingerprint') ? <Field label="TLS Fingerprint"><SelectField formRegister={form.register('tls_fingerprint')} options={tlsFingerprintOptions.map((value) => ({ value, label: value }))} /></Field> : null}
                      {enabledAdvanced.has('tls_alpn') ? <Field label="TLS ALPN"><SelectField formRegister={form.register('tls_alpn')} options={tlsAlpnOptions} /></Field> : null}
                    </>
                  ) : null}
                </div>
              </div>
            ) : null}
            {(enabledAdvanced.has('ss_method') || protocol === 'hysteria2' || protocol === 'tuic' || protocol === 'shadowtls') ? (
              <div className="advanced-group">
                <div className="advanced-group-title">{text('协议专属项')}</div>
                <div className="form-grid advanced-form-grid">
                  {enabledAdvanced.has('ss_method') ? <Field label={text('Shadowsocks 加密方法')}><SelectField formRegister={form.register('ss_method')} options={shadowsocksMethodOptions.map((value) => ({ value, label: value }))} /></Field> : null}
                  {protocol === 'hysteria2' ? (
                    <>
                      {enabledAdvanced.has('hy2_up_mbps') ? <Field label={text('HY2 上行 Mbps')}><input type="number" {...form.register('hy2_up_mbps')} /></Field> : null}
                      {enabledAdvanced.has('hy2_down_mbps') ? <Field label={text('HY2 下行 Mbps')}><input type="number" {...form.register('hy2_down_mbps')} /></Field> : null}
                      {enabledAdvanced.has('hy2_obfs') ? <Field label={text('HY2 混淆')}><SelectField formRegister={form.register('hy2_obfs')} options={hy2ObfsOptions} /></Field> : null}
                      {enabledAdvanced.has('hy2_obfs_password') ? <Field label={text('HY2 混淆密码')}><input {...form.register('hy2_obfs_password')} /></Field> : null}
                    </>
                  ) : null}
                  {protocol === 'tuic' ? (
                    <>
                      {enabledAdvanced.has('tuic_congestion_control') ? <Field label={text('TUIC 拥塞控制')}><SelectField formRegister={form.register('tuic_congestion_control')} options={tuicCongestionOptions.map((value) => ({ value, label: value }))} /></Field> : null}
                      {enabledAdvanced.has('tuic_zero_rtt') ? <label className="checkbox-field"><input type="checkbox" {...form.register('tuic_zero_rtt')} /> {text('启用 0-RTT')}</label> : null}
                    </>
                  ) : null}
                  {protocol === 'shadowtls' ? (
                    <>
                      {enabledAdvanced.has('shadowtls_version') ? <Field label={text('ShadowTLS 版本')}><select {...form.register('shadowtls_version')}><option value={3}>v3</option></select></Field> : null}
                    </>
                  ) : null}
                </div>
              </div>
            ) : null}
            </div>
        ) : null}
          </section>
        </div>
      </div>
    </Modal>
  );
}

export function ClientModal({ inbound, client, onClose, onSaved }: { inbound: Inbound | null; client?: Client; onClose: () => void; onSaved: () => void }) {
  const { showToast } = useToast();
  const { text } = useI18n();
  const [credentialOpen, setCredentialOpen] = useState(false);
  const form = useForm<ClientInput, unknown, ClientValues>({
    resolver: zodResolver(clientSchema),
    defaultValues: inbound ? clientFormValues(inbound, client) : undefined,
  });
  const clientOpenKey = inbound ? `${inbound.id}:${inbound.protocol}:${client?.id || 'new'}` : '';
  useEffect(() => {
    if (!inbound) return;
    form.reset(clientFormValues(inbound, client));
    setCredentialOpen(false);
  }, [clientOpenKey, form]);
  const regenerateCredential = () => {
    const generated = generatedClientCredentials(inbound?.protocol);
    form.setValue('uuid', generated.uuid, { shouldDirty: true, shouldValidate: true });
    form.setValue('credential_id', generated.credential_id, { shouldDirty: true, shouldValidate: true });
    form.setValue('password', generated.password, { shouldDirty: true, shouldValidate: true });
  };
  const save = useMutation({
    mutationFn: async (values: ClientValues) => {
      const payload = buildClientPayload(values, inbound!.protocol);
      const response = client ? await api.updateClient(inbound!.id, client.id, { ...client, ...payload }) : await api.createClient(inbound!.id, payload);
      return { payload, response };
    },
    onSuccess: ({ payload, response }) => {
      const warning = coreApplyWarning(response as CreateClientResponse, '客户端已保存，但核心配置未生效');
      showToast(text(warning || '客户端已保存'), warning ? coreApplyWarningTone(response) : 'success');
      onSaved();
      extractClientResponse(response, client, payload, inbound?.id || client?.inbound_id || 0);
      onClose();
    },
    onError: (error) => showToast(errorMessage(error, text('保存客户端失败')), 'error'),
  });
  const expiryMode = form.watch('expiry_mode');
  const credentialType = inboundCredentialType(inbound?.protocol || 'vless');
  const close = () => {
    onClose();
  };
  const credentialSummary = clientCredentialSummary(form.watch() as ClientValues, credentialType, text);
  return (
    <Modal
      open={!!inbound}
      title={text(client ? '编辑客户端' : '新增客户端')}
      onClose={close}
      footer={
        <>
          <button className="btn secondary" onClick={close}>{text('取消')}</button>
          <SpinnerButton className="btn primary" loading={save.isPending} onClick={form.handleSubmit((values) => save.mutate(values))}>{text('保存')}</SpinnerButton>
        </>
      }
    >
      <div className="form-grid">
        <div className="form-section-heading span-2">
          <div>
            <div className="form-section-kicker">{text('基本信息')}</div>
            <h3>{text('客户端身份')}</h3>
          </div>
          <div className="form-section-summary">{text(form.watch('enabled') ? '已启用' : '已停用')}</div>
        </div>
        <Field label={text('客户端名称')}><input {...form.register('email')} /><FieldError message={form.formState.errors.email?.message ? text(form.formState.errors.email.message) : undefined} /></Field>
        <Field label={text('状态')}>
          <SwitchField checked={form.watch('enabled') ?? true} inputProps={form.register('enabled')} text={text} />
        </Field>
        <div className="form-section-heading span-2">
          <div>
            <div className="form-section-kicker">{text('用量与到期')}</div>
            <h3>{text('访问控制')}</h3>
          </div>
        </div>
        <Field label={text('流量限额（GB，0 不限制）')}><input type="number" step="0.1" {...form.register('traffic_limit_gb')} /></Field>
        <Field label={text('到期时间')}>
          <select {...form.register('expiry_mode')}>
            <option value="unlimited">{text('不限制')}</option>
            <option value="30d">{text('30 天')}</option>
            <option value="90d">{text('90 天')}</option>
            <option value="custom">{text('自定义日期')}</option>
          </select>
        </Field>
        {expiryMode === 'custom' ? <Field label={text('自定义到期日期')}><input type="date" {...form.register('expiry_date')} /></Field> : null}
        <div className="credential-summary-panel span-2">
          <div>
            <strong>{text('凭据')}</strong>
            <span>{credentialSummary}</span>
          </div>
          <button className="advanced-toggle" type="button" onClick={() => setCredentialOpen((open) => !open)} aria-expanded={credentialOpen}>
            <ChevronDown className={credentialOpen ? 'h-4 w-4 rotate-180' : 'h-4 w-4'} />
            {text(credentialOpen ? '收起' : '展开编辑')}
          </button>
        </div>
        {credentialOpen ? (
          <div className="advanced-panel span-2">
            <CredentialFields credentialType={credentialType} form={form} regenerateCredential={regenerateCredential} text={text} client={client} regenerateLabel="重新生成客户端凭据" />
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

export function savedClientLinkActions(protocol: string): Array<'share'> {
  return supportsInboundShareLink(protocol) ? ['share'] : [];
}

function CredentialFields({
  credentialType,
  form,
  regenerateCredential,
  regenerateLabel = '重新生成',
  text,
  client,
}: {
  credentialType: ReturnType<typeof inboundCredentialType>;
  form: ReturnType<typeof useForm<ClientInput, unknown, ClientValues>>;
  regenerateCredential: () => void;
  regenerateLabel?: string;
  text: (value: string) => string;
  client?: Client;
}) {
  const help = text(client ? '现有凭据会反显，可手动修改。' : '默认自动生成，可在保存前手动修改。');
  const regenButton = (
    <button className="icon-button" type="button" onClick={regenerateCredential} title={text(regenerateLabel)}>
      <RotateCcw className="h-4 w-4" />
    </button>
  );
  if (credentialType === 'none') {
    return <div className="advanced-note">{text('该协议使用节点级凭据，客户端不需要单独连接凭据。')}</div>;
  }
  if (credentialType === 'credential_id_password') {
    return (
      <>
        <Field label="TUIC UUID" help={help}>
          <div className="input-action-row">
            <input {...form.register('credential_id')} />
            {regenButton}
            <CopyCredentialButton value={form.watch('credential_id') || ''} label="TUIC UUID" text={text} />
          </div>
        </Field>
        <Field label={text('TUIC 密码')}><CredentialInput formRegister={form.register('password')} value={form.watch('password') || ''} label="TUIC 密码" text={text} /></Field>
      </>
    );
  }
  if (credentialType === 'username_password') {
    return (
      <>
        <Field label={text('用户名')} help={help}>
          <div className="input-action-row">
            <input {...form.register('credential_id')} />
            {regenButton}
            <CopyCredentialButton value={form.watch('credential_id') || ''} label="用户名" text={text} />
          </div>
        </Field>
        <Field label={text('密码')}><CredentialInput formRegister={form.register('password')} value={form.watch('password') || ''} label="密码" text={text} /></Field>
      </>
    );
  }
  if (credentialType === 'password') {
    return (
      <Field label={text('密码')} help={help}>
        <div className="input-action-row">
          <input {...form.register('password')} />
          {regenButton}
          <CopyCredentialButton value={form.watch('password') || ''} label="密码" text={text} />
        </div>
      </Field>
    );
  }
  return (
    <Field label="UUID" help={help}>
      <div className="input-action-row">
        <input {...form.register('uuid')} />
        {regenButton}
        <CopyCredentialButton value={form.watch('uuid') || ''} label="UUID" text={text} />
      </div>
      <FieldError message={form.formState.errors.uuid?.message ? text(form.formState.errors.uuid.message) : undefined} />
    </Field>
  );
}

function SelectField({ formRegister, options }: { formRegister: UseFormRegisterReturn; options: Array<{ value: string; label: string }> }) {
  return (
    <select {...formRegister}>
      {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
    </select>
  );
}

function SwitchField({ checked, inputProps, text }: { checked: boolean; inputProps: UseFormRegisterReturn; text: (value: string) => string }) {
  return (
    <span className="toggle-switch-field">
      <input type="checkbox" {...inputProps} />
      <span className="toggle-switch-track" aria-hidden="true"><span /></span>
      <strong>{text(checked ? '已启用' : '已停用')}</strong>
    </span>
  );
}

function CredentialInput({ formRegister, value, label, text }: { formRegister: UseFormRegisterReturn; value: string; label: string; text: (value: string) => string }) {
  return (
    <div className="input-action-row">
      <input {...formRegister} />
      <CopyCredentialButton value={value} label={label} text={text} />
    </div>
  );
}

function CopyCredentialButton({ value, label, text }: { value: string; label: string; text: (value: string) => string }) {
  const { showToast } = useToast();
  return (
    <button
      className="icon-button"
      type="button"
      disabled={!value}
      onClick={() => copyText(value, text(`${label}已复制`), text('复制失败'), showToast)}
      title={text(`复制${label}`)}
    >
      <Copy className="h-4 w-4" />
    </button>
  );
}

function clientCredentialSummary(values: ClientValues, credentialType: ReturnType<typeof inboundCredentialType>, text: (value: string) => string) {
  if (credentialType === 'none') return text('该协议使用节点级凭据');
  if (credentialType === 'credential_id_password') return `TUIC UUID: ${maskCredential(values.credential_id || values.uuid, text)} / ${text('密码')}: ${maskCredential(values.password, text)}`;
  if (credentialType === 'username_password') return `${text('用户名')}: ${maskCredential(values.credential_id || values.uuid, text)} / ${text('密码')}: ${maskCredential(values.password, text)}`;
  if (credentialType === 'password') return `${text('密码')}: ${maskCredential(values.password || values.uuid, text)}`;
  return `UUID: ${maskCredential(values.uuid || values.credential_id, text)}`;
}

function templateDisplayParts(label: string) {
  const match = label.match(/^(.+?)[：:]\s*(.+)$/);
  if (!match) return { name: label, combo: '' };
  return { name: match[1].trim(), combo: match[2].trim() };
}

function maskCredential(value: string | undefined, text: (value: string) => string) {
  const current = String(value || '');
  if (!current) return text('未生成');
  if (current.length <= 12) return current;
  return `${current.slice(0, 8)}...${current.slice(-4)}`;
}

function generatedClientCredentials(protocol?: string) {
  return generatedClientCredentialValues(protocol);
}

function randomHex(bytes: number) {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, '0')).join('');
}

function extractClientResponse(response: unknown, fallback?: Client, payload?: ReturnType<typeof buildClientPayload>, inboundId = 0): Client | null {
  if (isClient(response)) return response;
  if (response && typeof response === 'object' && isClient((response as { client?: unknown }).client)) return (response as { client: Client }).client;
  if (!payload) return fallback || null;
  return {
    id: fallback?.id || 0,
    inbound_id: fallback?.inbound_id || inboundId,
    email: payload.email,
    uuid: payload.uuid,
    credential_id: payload.credential_id,
    password: payload.password,
    subscription_token: fallback?.subscription_token,
    enabled: payload.enabled,
    traffic_limit: payload.traffic_limit,
    expiry_at: payload.expiry_at,
  };
}

function isClient(value: unknown): value is Client {
  return Boolean(value && typeof value === 'object' && 'uuid' in value && 'email' in value);
}

async function copyText(value: string, title: string, errorTitle: string, showToast: (title: string, tone?: 'success' | 'error' | 'info') => void) {
  try {
    await copyToClipboard(value);
    showToast(title, 'success');
  } catch {
    showToast(errorTitle, 'error');
  }
}

function errorMessage(error: unknown, fallback: string) {
  return getAPIErrorMessage(error, fallback);
}
