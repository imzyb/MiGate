import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfirmProvider, ToastProvider } from '../components/ui';
import { I18nProvider } from '../lib/i18n';
import OutboundsPage from './OutboundsPage';

const apiMock = vi.hoisted(() => ({
  outbounds: vi.fn(async () => []),
  outboundSubscriptions: vi.fn(async () => []),
  speedtestAll: vi.fn(async () => ({})),
  refreshOutboundSubscriptions: vi.fn(async () => ({})),
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

describe('OutboundsPage simplified actions', () => {
  it('keeps node-pool import as a common action and moves only maintenance actions behind more', async () => {
    renderOutbounds();

    await vi.waitFor(() => expect(document.body.textContent).toContain('出站管理'));
    const titleActions = document.querySelector('.page-title-actions');
    expect(titleActions?.textContent).toContain('新增出站');
    expect(titleActions?.textContent).toContain('添加订阅');
    expect(titleActions?.textContent).toContain('导入代理池');
    expect(titleActions?.textContent).toContain('更多');
    expect(titleActions?.textContent).not.toContain('刷新订阅');
    expect(titleActions?.textContent).not.toContain('批量测速');
  });

  it('opens the more-actions menu when clicking the more button', async () => {
    renderOutbounds();

    await vi.waitFor(() => expect(document.body.textContent).toContain('出站管理'));
    expect(document.querySelector('.more-actions-menu')).toBeNull();

    await act(async () => {
      clickButtonByText('更多');
    });

    const menu = document.querySelector('.more-actions-menu');
    expect(menu?.textContent).toContain('刷新订阅');
    expect(menu?.textContent).toContain('批量测速');
    expect(menu?.textContent).not.toContain('导入代理池');
  });
});

function clickButtonByText(label: string) {
  const button = Array.from(document.querySelectorAll('button')).find((item) => item.textContent?.includes(label));
  if (!button) throw new Error(`button not found: ${label}`);
  button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
}

function renderOutbounds() {
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
              <OutboundsPage />
            </ConfirmProvider>
          </ToastProvider>
        </QueryClientProvider>
      </I18nProvider>,
    );
  });
}
