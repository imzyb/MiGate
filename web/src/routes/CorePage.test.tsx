import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfirmProvider, ToastProvider } from '../components/ui';
import { I18nProvider } from '../lib/i18n';
import CorePage from './CorePage';

const apiMock = vi.hoisted(() => ({
  xrayStatus: vi.fn(async () => ({ status: 'running', managed: true, config_path: '/etc/migate/cores/xray.json' })),
  xrayVersion: vi.fn(async () => ({ version: '1.0.0' })),
  xrayConfig: vi.fn(async () => ({})),
  xrayConfigPreview: vi.fn(async () => ({ config_path: '/etc/migate/cores/xray.json', inbounds: [] })),
  xrayDiagnostics: vi.fn(async () => ({ managed: true, service_status: 'running', config_path: '/etc/migate/cores/xray.json', ports: [], checks: [] })),
  xrayLogs: vi.fn(async () => ''),
  xrayValidate: vi.fn(async () => ({ valid: true })),
  xrayApply: vi.fn(async () => ({ ok: true })),
  xrayInstall: vi.fn(async () => ({ ok: true })),
  xrayUninstall: vi.fn(async () => ({ ok: true })),
  xrayDelete: vi.fn(async () => ({ ok: true })),
  xrayRestart: vi.fn(async () => ({ ok: true })),
  xrayStop: vi.fn(async () => ({ ok: true })),
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

describe('CorePage simplified maintenance', () => {
  it('keeps dangerous and raw diagnostic controls collapsed by default', async () => {
    renderCore();

    await vi.waitFor(() => expect(document.body.textContent).toContain('Xray 核心管理'));
    expect(document.body.textContent).toContain('高级维护');
    expect(document.body.textContent).not.toContain('危险');
    expect(document.body.textContent).not.toContain('停止核心');
    expect(document.body.textContent).not.toContain('取消托管核心');
    expect(document.body.textContent).not.toContain('删除核心');
    expect(document.body.textContent).not.toContain('配置预览');
    expect(document.body.textContent).not.toContain('最近日志');
  });
});

function renderCore() {
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
              <CorePage core="xray" />
            </ConfirmProvider>
          </ToastProvider>
        </QueryClientProvider>
      </I18nProvider>,
    );
  });
}
