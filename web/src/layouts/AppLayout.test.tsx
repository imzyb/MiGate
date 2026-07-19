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

    for (const label of ['概览', '入站', '出站', '核心', '路由', '链路', '设置']) {
      expect(nav?.textContent).toContain(label);
    }
    expect(nav?.querySelector('a[href="/routing"]')?.textContent).toContain('路由');
    for (const hiddenLabel of ['拓扑', 'Xray', 'Sing-box']) {
      expect(nav?.textContent).not.toContain(hiddenLabel);
    }
  });

  it('keeps DOM structure and non-text attributes stable when switching languages', async () => {
    renderLayout('/');

    await vi.waitFor(() => expect(document.body.textContent).toContain('概览'));
    const shell = document.querySelector('.min-h-screen') as HTMLElement;
    const before = structuralSnapshot(shell);

    const languageButton = document.querySelector('button[aria-label="语言切换"]') as HTMLButtonElement;
    expect(languageButton).toBeTruthy();
    act(() => languageButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));

    await vi.waitFor(() => expect(document.body.textContent).toContain('Overview'));
    expect(structuralSnapshot(shell)).toEqual(before);
  });

  it('gives every icon-only layout button an aria-label', async () => {
    renderLayout('/');

    await vi.waitFor(() => expect(document.body.textContent).toContain('MiGate'));
    const unlabeledIconButtons = Array.from(document.querySelectorAll('button.icon-button')).filter((button) => {
      const hasOnlyIcon = button.textContent?.trim() === '';
      return hasOnlyIcon && !button.getAttribute('aria-label');
    });

    expect(unlabeledIconButtons).toEqual([]);
  });
});

function structuralSnapshot(rootElement: HTMLElement) {
  return Array.from(rootElement.querySelectorAll('*')).map((element) => ({
    tag: element.tagName,
    className: element.getAttribute('class'),
    href: element.getAttribute('href'),
    role: element.getAttribute('role'),
    type: element.getAttribute('type'),
    childElementCount: element.childElementCount,
  }));
}

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
