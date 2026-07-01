import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfirmProvider, ToastProvider } from '../components/ui';
import { I18nProvider } from '../lib/i18n';
import SettingsPage from './SettingsPage';

const apiMock = vi.hoisted(() => ({
  session: vi.fn(async () => ({ auth_enabled: true, authenticated: true, username: 'sam', default_password: false })),
  settings: vi.fn(async () => ({
    panel_port: 8080,
    web_base_path: '/',
    panel_username: 'admin',
    has_password: true,
    database_path: '/etc/migate/migate.db',
    management_direct_enabled: true,
    management_direct_auto_detect: true,
  })),
  saveSettings: vi.fn(async () => ({})),
  certStatus: vi.fn(async () => ({})),
  certificates: vi.fn(async () => ({ certificates: [] })),
  certificateInboundTargets: vi.fn(async () => ({ inbounds: [] })),
  updateStatus: vi.fn(async () => ({ status: 'idle' })),
  updateCheck: vi.fn(async () => ({ current_version: 'v1.5.5', latest_version: 'v1.5.5', update_available: false })),
  version: vi.fn(async () => ({ version: 'v1.5.5' })),
  updateLogs: vi.fn(async () => ({ logs: '', path: '/var/log/migate-update.log' })),
  sessions: vi.fn(async () => []),
  serviceStatus: vi.fn(async () => ({ status: 'running', service: 'migate' })),
  restart: vi.fn(async () => ({})),
  issueCert: vi.fn(async () => ({})),
  certificatePreflight: vi.fn(async () => ({ preflight: null })),
  createCertificate: vi.fn(async () => ({ preflight: null })),
  importCertificate: vi.fn(async () => ({})),
  renewDueCertificates: vi.fn(async () => ({ renewal: { renewed: [] } })),
  applyCertificate: vi.fn(async () => ({})),
  deleteCertificate: vi.fn(async () => ({})),
  update: vi.fn(async () => ({})),
  revokeSession: vi.fn(async () => ({})),
}));

vi.mock('../api/endpoints', () => ({ api: apiMock }));

let root: Root | null = null;
let container: HTMLDivElement | null = null;

afterEach(() => {
  if (root) act(() => root?.unmount());
  root = null;
  container?.remove();
  container = null;
  vi.clearAllMocks();
});

describe('SettingsPage simplified panel configuration', () => {
  it('does not show redundant summary tiles above the panel settings form', async () => {
    renderSettings();

    await vi.waitFor(() => expect(document.body.textContent).toContain('面板配置'));
    expect(document.querySelector('.panel-config-summary')).toBeNull();
    expect(document.body.textContent).not.toContain('认证状态');
    expect(document.body.textContent).not.toContain('本地配置库');
    expect(document.body.textContent).toContain('访问入口');
    expect(document.body.textContent).toContain('面板端口');
    expect(document.body.textContent).toContain('Web 基础路径');
  });
});

function renderSettings() {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  act(() => {
    root!.render(
      <I18nProvider>
        <QueryClientProvider client={queryClient}>
          <ToastProvider>
            <ConfirmProvider>
              <SettingsPage />
            </ConfirmProvider>
          </ToastProvider>
        </QueryClientProvider>
      </I18nProvider>,
    );
  });
}
