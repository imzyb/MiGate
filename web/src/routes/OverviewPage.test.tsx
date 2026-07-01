import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '../lib/i18n';
import OverviewPage from './OverviewPage';

const apiMock = vi.hoisted(() => ({
  dashboardSummary: vi.fn(async () => ({
    counts: {
      inbounds: 2,
      inbounds_enabled: 2,
      clients: 3,
      clients_active: 2,
      clients_expired: 1,
      clients_limited: 0,
      outbounds: 4,
      outbounds_enabled: 3,
      routing_rules: 5,
      routing_enabled: 4,
    },
    protocols: { vless: 1, hysteria2: 1 },
    validation: { xray: { valid: true }, singbox: { valid: true } },
  })),
  trafficV2Snapshot: vi.fn(async () => ({
    generated_at: 'now',
    observed_at: 'now',
    window_seconds: 5,
    total: {
      cumulative: { up: 1024, down: 2048, total: 3072, status: 'ok', source: 'migate', message: '' },
      realtime: { delta_up: 10, delta_down: 20, delta_total: 30, rate_up: 10, rate_down: 20, rate_total: 30, observed_at: 'now', window_seconds: 5, status: 'ok', source: 'inbound', message: '' },
    },
    inbounds: [],
    clients: [],
    coverage: { overall: 'ok', engines: { xray: 'ok', singbox: 'ok' }, ok: 2, waiting: 0, stale: 0, unavailable: 0, unsupported: 0, partial: 0 },
  })),
  trafficV2Analytics: vi.fn(async () => ({ points: [], ranks: [] })),
  resources: vi.fn(async () => ({ cpu_percent: 1, memory: { used: 1, total: 2, percent: 50 }, disk: { used: 1, total: 2, percent: 50 } })),
  xrayStatus: vi.fn(async () => ({ status: 'running', version: '1.0.0' })),
  singboxStatus: vi.fn(async () => ({ status: 'running', version: '1.0.0' })),
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

describe('OverviewPage simplified dashboard', () => {
  it('shows four primary metric cards and keeps secondary details collapsed', async () => {
    renderOverview();

    await vi.waitFor(() => expect(document.body.textContent).toContain('运行概览'));
    expect(document.querySelectorAll('.metric-card')).toHaveLength(4);
    expect(document.body.textContent).toContain('节点/客户端');
    expect(document.body.textContent).toContain('核心状态');
    expect(document.body.textContent).not.toContain('路由规则');
    expect(document.body.textContent).not.toContain('协议分布');
    expect(document.body.textContent).toContain('更多运行详情');
  });
});

function renderOverview() {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  act(() => {
    root!.render(
      <I18nProvider>
        <QueryClientProvider client={queryClient}>
          <OverviewPage />
        </QueryClientProvider>
      </I18nProvider>,
    );
  });
}
