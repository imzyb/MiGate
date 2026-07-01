import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../components/ui';
import { I18nProvider } from '../lib/i18n';
import AppLayout from './AppLayout';

const apiMock = vi.hoisted(() => ({
  session: vi.fn(async () => ({ auth_enabled: true, authenticated: true, username: 'sam' })),
  version: vi.fn(async () => ({ version: 'v-test' })),
  logout: vi.fn(async () => ({})),
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

describe('AppLayout simplified navigation', () => {
  it('keeps the primary sidebar focused on common MiGate tasks', async () => {
    renderLayout('/');

    await vi.waitFor(() => expect(document.body.textContent).toContain('MiGate'));
    const nav = document.querySelector('aside nav');

    for (const label of ['概览', '入站', '出站', '核心', '链路', '设置']) {
      expect(nav?.textContent).toContain(label);
    }
    for (const hiddenLabel of ['拓扑', 'Xray', 'Sing-box', '路由']) {
      expect(nav?.textContent).not.toContain(hiddenLabel);
    }
  });
});

function renderLayout(initialPath: string) {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  act(() => {
    root!.render(
      <I18nProvider>
        <QueryClientProvider client={queryClient}>
          <ToastProvider>
            <MemoryRouter initialEntries={[initialPath]}>
              <Routes>
                <Route element={<AppLayout />}>
                  <Route path="*" element={<div>content</div>} />
                </Route>
              </Routes>
            </MemoryRouter>
          </ToastProvider>
        </QueryClientProvider>
      </I18nProvider>,
    );
  });
}
