import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfirmProvider, ToastProvider } from '../components/ui';
import type { Client, Inbound } from '../api/types';
import { I18nProvider } from '../lib/i18n';
import { createDefaultInbound } from './InboundsPage';
import { ClientModal, InboundModal } from './InboundsPageForms';

const apiMock = vi.hoisted(() => ({
  certStatus: vi.fn(async () => ({ issued: false, cert_path: '', key_path: '', domain: '' })),
  generateRealityKeypair: vi.fn(async () => ({ private_key: 'private', public_key: 'public' })),
  createInbound: vi.fn(async (body): Promise<unknown> => ({ inbound: { id: 99, clients: [], ...body } })),
  updateInbound: vi.fn(async (_id, body) => ({ inbound: body })),
  createClient: vi.fn(async (_inboundId, body): Promise<unknown> => ({ client: { id: 7, inbound_id: _inboundId, ...body } })),
  updateClient: vi.fn(async (_inboundId, id, body) => ({ client: { id, inbound_id: _inboundId, ...body } })),
}));

vi.mock('../api/endpoints', () => ({
  api: apiMock,
}));

let root: Root | null = null;
let container: HTMLDivElement | null = null;

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  root = null;
  container?.remove();
  container = null;
  vi.clearAllMocks();
});

describe('inbound and client modal credential behavior', () => {
  it('keeps client UUID stable across parent rerenders and inbound object reference changes', () => {
    const inbound = inboundWithClient();
    const client = inbound.clients![0];
    renderModal(<ClientModal inbound={inbound} client={client} onClose={() => undefined} onSaved={() => undefined} />);

    openCredentialSection();
    const initial = inputByLabel('UUID').value;

    const refreshedInbound = { ...inbound, traffic_total: 2048, clients: [{ ...client, up: 128 }] };
    renderModal(<ClientModal inbound={refreshedInbound} client={refreshedInbound.clients![0]} onClose={() => undefined} onSaved={() => undefined} />);

    expect(inputByLabel('UUID').value).toBe(initial);
  });

  it('regenerates client credentials only when the user clicks regenerate', () => {
    const inbound = inboundWithClient();
    const client = inbound.clients![0];
    renderModal(<ClientModal inbound={inbound} client={client} onClose={() => undefined} onSaved={() => undefined} />);

    openCredentialSection();
    const initial = inputByLabel('UUID').value;
    clickButtonByTitle('重新生成客户端凭据');

    expect(inputByLabel('UUID').value).not.toBe(initial);
  });

  it('regenerates the default client credential when a new node protocol changes', () => {
    renderModal(<InboundModal inbound={createDefaultInbound()} onClose={() => undefined} onSaved={() => undefined} />);

    openCredentialSection('客户端凭据');
    const initial = inputByLabel('UUID').value;
    clickButtonByText('高级设置');
    const protocol = inputByLabel('协议') as HTMLSelectElement;
    changeValue(protocol, 'tuic');

    expect(inputByLabel('TUIC UUID').value).not.toBe(initial);
    expect(inputByLabel('TUIC 密码').value).not.toBe('');
  });

  it('uses parsed default client values when creating a node', async () => {
    renderModal(<InboundModal inbound={createDefaultInbound()} onClose={() => undefined} onSaved={() => undefined} />);

    changeValue(inputByLabel('名称'), 'edge');
    changeValue(inputByLabel('流量限额'), '1.5');
    clickButtonByText('保存');

    await vi.waitFor(() => expect(apiMock.createInbound).toHaveBeenCalled());
    const payload = apiMock.createInbound.mock.calls[0][0];
    expect(payload.initial_client.traffic_limit).toBe(Math.round(1.5 * 1024 ** 3));
  });

  it('shows a warning when a created hysteria2 node is saved but sing-box apply fails', async () => {
    apiMock.createInbound.mockResolvedValueOnce({ created: true, applied: false, detail: 'invalid config', inbound: { ...createDefaultInbound(), id: 99, clients: [], protocol: 'hysteria2' } });
    renderModal(<InboundModal inbound={createDefaultInbound()} onClose={() => undefined} onSaved={() => undefined} />);

    clickButtonByText('高级设置');
    changeValue(inputByLabel('协议'), 'hysteria2');
    changeValue(inputByLabel('名称'), 'hy2 edge');
    clickButtonByText('保存');

    await waitForText('节点已保存，但核心配置未生效：invalid config');
  });

  it('shows a warning when a created tuic client is saved but sing-box apply fails', async () => {
    apiMock.createClient.mockResolvedValueOnce({ created: true, applied: false, singbox: { applied: false, detail: 'restart failed' }, client: { id: 7, inbound_id: 3, email: 'phone', uuid: 'uuid', enabled: true } });
    const inbound = { ...createDefaultInbound(), id: 3, protocol: 'tuic', core: 'sing-box', clients: [] };
    renderModal(<ClientModal inbound={inbound} onClose={() => undefined} onSaved={() => undefined} />);

    changeValue(inputByLabel('客户端名称'), 'phone');
    clickButtonByText('保存');

    await waitForText('客户端已保存，但核心配置未生效：restart failed');
  });

  it('keeps normal success toast when a node is saved and applied', async () => {
    apiMock.createInbound.mockResolvedValueOnce({ created: true, applied: true, inbound: { ...createDefaultInbound(), id: 99, clients: [] } });
    renderModal(<InboundModal inbound={createDefaultInbound()} onClose={() => undefined} onSaved={() => undefined} />);

    changeValue(inputByLabel('名称'), 'edge');
    clickButtonByText('保存');

    await waitForText('节点已保存');
    expect(document.body.textContent).not.toContain('sing-box 配置未生效');
  });

  it('fills the TLS SNI and WS/H2 host with the settings certificate domain when attaching the certificate', async () => {
    apiMock.certStatus.mockResolvedValueOnce({
      issued: true,
      cert_path: '/etc/migate/certs/hkcm.example.kg/fullchain.pem',
      key_path: '/etc/migate/certs/hkcm.example.kg/privkey.key',
      domain: 'hkcm.example.kg',
    });
    renderModal(<InboundModal inbound={{ ...createDefaultInbound(), id: 8, protocol: 'vmess', network: 'ws', security: 'tls', tls_sni: 'example.com', ws_host: 'example.com' }} onClose={() => undefined} onSaved={() => undefined} />);

    await vi.waitFor(() => {
      expect(buttonByText('使用设置页证书')).not.toBeDisabled();
    });
    clickButtonByText('使用设置页证书');

    expect(inputByLabel('域名 / SNI').value).toBe('hkcm.example.kg');
    clickButtonByText('高级设置');
    expect(inputByLabel('WS/H2 主机').value).toBe('hkcm.example.kg');
    expect(inputByLabel('TLS 私钥文件').value).toBe('/etc/migate/certs/hkcm.example.kg/privkey.key');
  });

  it('keeps a custom WS/H2 host when attaching the settings certificate', async () => {
    apiMock.certStatus.mockResolvedValueOnce({
      issued: true,
      cert_path: '/etc/migate/certs/hkcm.example.kg/fullchain.pem',
      key_path: '/etc/migate/certs/hkcm.example.kg/privkey.key',
      domain: 'hkcm.example.kg',
    });
    renderModal(<InboundModal inbound={{ ...createDefaultInbound(), id: 9, protocol: 'vmess', network: 'ws', security: 'tls', tls_sni: 'old.example.com', ws_host: 'cdn.example.com' }} onClose={() => undefined} onSaved={() => undefined} />);

    await vi.waitFor(() => {
      expect(buttonByText('使用设置页证书')).not.toBeDisabled();
    });
    clickButtonByText('使用设置页证书');
    clickButtonByText('高级设置');

    expect(inputByLabel('域名 / SNI').value).toBe('hkcm.example.kg');
    expect(inputByLabel('WS/H2 主机').value).toBe('cdn.example.com');
  });
});

function renderModal(node: React.ReactNode) {
  if (!container) {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  }
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  act(() => {
    root!.render(
      <I18nProvider>
        <QueryClientProvider client={queryClient}>
          <ToastProvider>
            <ConfirmProvider>{node}</ConfirmProvider>
          </ToastProvider>
        </QueryClientProvider>
      </I18nProvider>,
    );
  });
}

function inboundWithClient(): Inbound {
  const inbound = { ...createDefaultInbound(), id: 1, remark: 'edge', uuid: 'inbound-id' };
  const client: Client = {
    id: 10,
    inbound_id: 1,
    email: 'phone',
    uuid: '11111111-1111-4111-8111-111111111111',
    credential_id: '11111111-1111-4111-8111-111111111111',
    enabled: true,
    traffic_limit: 0,
    expiry_at: 0,
  };
  return { ...inbound, clients: [client] };
}

function openCredentialSection(label = '展开编辑') {
  clickButtonByText(label);
}

function inputByLabel(label: string) {
  const field = Array.from(document.querySelectorAll('label')).find((item) => item.textContent?.includes(label));
  const input = field?.querySelector('input, select') as HTMLInputElement | HTMLSelectElement | null;
  if (!input) throw new Error(`missing input: ${label}`);
  return input;
}

function clickButtonByText(text: string) {
  const button = buttonByText(text);
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
}

function buttonByText(text: string) {
  const button = Array.from(document.querySelectorAll('button')).find((item) => item.textContent?.includes(text));
  if (!button) throw new Error(`missing button text: ${text}`);
  return button as HTMLButtonElement;
}

function clickButtonByTitle(title: string) {
  const button = document.querySelector(`button[title="${title}"]`);
  if (!button) throw new Error(`missing button title: ${title}`);
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
}

function changeValue(input: HTMLInputElement | HTMLSelectElement, value: string) {
  act(() => {
    const prototype = input instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

async function waitForText(text: string) {
  await vi.waitFor(() => {
    expect(document.body.textContent).toContain(text);
  });
}
