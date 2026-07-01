import { describe, expect, it, vi } from 'vitest';
import { api } from './endpoints';
import { ApiError, appPath, basePath, apiFetch, getAPIErrorMessage } from './client';

describe('api client', () => {
  it('detects base path from panel routes', () => {
    window.history.replaceState({}, '', '/panel/login');
    expect(basePath()).toBe('/panel');
    expect(appPath('/api/session')).toBe('/panel/api/session');
  });

  it('keeps the base path on nested SPA routes', () => {
    window.__MIGATE_BASE_PATH__ = undefined;
    window.history.replaceState({}, '', '/panel');
    expect(basePath()).toBe('/panel');
    expect(appPath('/api/session')).toBe('/panel/api/session');

    window.history.replaceState({}, '', '/panel/inbounds');
    expect(basePath()).toBe('/panel');
    expect(appPath('/api/inbounds')).toBe('/panel/api/inbounds');
    expect(appPath('/sub/client-token')).toBe('/panel/sub/client-token');

    window.history.replaceState({}, '', '/panel/settings');
    expect(basePath()).toBe('/panel');
    expect(appPath('/login')).toBe('/panel/login');

    window.history.replaceState({}, '', '/panel/topology');
    expect(basePath()).toBe('/panel');
    expect(appPath('/api/routing-rules')).toBe('/panel/api/routing-rules');

    window.history.replaceState({}, '', '/panel/core/singbox');
    expect(basePath()).toBe('/panel');
    expect(appPath('/api/singbox/status')).toBe('/panel/api/singbox/status');

    window.history.replaceState({}, '', '/foo/panel/inbounds');
    expect(basePath()).toBe('/foo/panel');
    expect(appPath('/api/inbounds')).toBe('/foo/panel/api/inbounds');
  });

  it('uses the backend-injected base path when present', () => {
    window.__MIGATE_BASE_PATH__ = '/panel';
    window.history.replaceState({}, '', '/panel/routing');
    expect(basePath()).toBe('/panel');
    expect(appPath('/api/routing-rules')).toBe('/panel/api/routing-rules');
    window.__MIGATE_BASE_PATH__ = undefined;
  });

  it('prefers standard backend error message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: { code: 'duplicate_client', message: 'Email already exists' }, message: 'top-level message' }), { status: 409, headers: { 'content-type': 'application/json' } })),
    );
    await expect(apiFetch('/api/test')).rejects.toMatchObject({ status: 409, message: 'Email already exists' });
    vi.unstubAllGlobals();
  });

  it('reads standard backend error objects', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: { code: 'invalid_json', message: 'Invalid JSON body', detail: 'body parse failed', fields: { field: 'body' } } }), { status: 400, headers: { 'content-type': 'application/json' } })),
    );
    await expect(apiFetch('/api/test')).rejects.toMatchObject({
      status: 400,
      message: 'Invalid JSON body',
      code: 'invalid_json',
      detail: 'body parse failed',
      fields: { field: 'body' },
    });
    vi.unstubAllGlobals();
  });

  it('keeps structured preflight fields from standard error objects', async () => {
    const preflight = { ok: false, checks: [{ code: 'domain_not_resolved', status: 'failed', detail: 'example.com' }] };
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: { code: 'preflight_failed', fields: { preflight } } }), { status: 400, headers: { 'content-type': 'application/json' } })),
    );
    await expect(apiFetch('/api/certificates')).rejects.toMatchObject({
      status: 400,
      code: 'preflight_failed',
      fields: { preflight },
    });
    vi.unstubAllGlobals();
  });

  it('uses standard backend error code when message is absent', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: { code: 'confirmation_required' } }), { status: 403, headers: { 'content-type': 'application/json' } })),
    );
    await expect(apiFetch('/api/test')).rejects.toMatchObject({ status: 403, message: 'confirmation_required' });
    vi.unstubAllGlobals();
  });

  it('does not read removed legacy error payload fields', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: 'legacy_code', message: 'legacy message' }), { status: 400, headers: { 'content-type': 'application/json' } })),
    );
    await expect(apiFetch('/api/test')).rejects.toMatchObject({ status: 400, message: 'request_failed' });
    vi.unstubAllGlobals();
  });

  it('formats only standard API client errors for UI messages', () => {
    expect(getAPIErrorMessage(new ApiError(409, 'Email already exists', { error: { code: 'duplicate_client' } }, { code: 'duplicate_client' }), 'fallback')).toBe('Email already exists');
    expect(getAPIErrorMessage(new Error('generic failure'), 'fallback')).toBe('fallback');
    expect(getAPIErrorMessage('plain failure', 'fallback')).toBe('fallback');
  });

  it('keeps outbound fields when toggling enabled state', async () => {
    window.history.replaceState({}, '', '/');
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.method).toBe('PUT');
      expect(JSON.parse(String(init?.body))).toMatchObject({
        id: 9,
        tag: 'proxy-socks',
        protocol: 'socks',
        address: '127.0.0.1',
        port: 1080,
        enabled: false,
      });
      return new Response(JSON.stringify({ status: 'ok' }), { status: 200, headers: { 'content-type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    await api.toggleOutbound({ id: 9, tag: 'proxy-socks', protocol: 'socks', address: '127.0.0.1', port: 1080, enabled: true }, false);
    expect(fetchMock).toHaveBeenCalledWith('/api/outbounds/9', expect.any(Object));
    vi.unstubAllGlobals();
  });

  it('unwraps routing rule save responses', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.method).toBe('POST');
      return new Response(JSON.stringify({ rule: { id: 3, inbound_tag: 'edge', outbound_tag: 'direct', enabled: true }, xray: { status: 'applied' } }), { status: 201, headers: { 'content-type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    await expect(api.createRoutingRule({ inbound_tag: 'edge', outbound_tag: 'direct', enabled: true })).resolves.toMatchObject({
      id: 3,
      inbound_tag: 'edge',
      outbound_tag: 'direct',
    });
    vi.unstubAllGlobals();
  });

  it('sends explicit confirmation for core system actions', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.method).toBe('POST');
      expect(JSON.parse(String(init?.body))).toMatchObject({ confirm: true, allow_system_changes: true });
      return new Response(JSON.stringify({ status: 'ok' }), { status: 200, headers: { 'content-type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    await api.xrayApply();
    await api.xrayInstall();
    await api.xrayUninstall();
    await api.xrayDelete();
    await api.xrayRestart();
    await api.xrayStop();
    await api.singboxApply();
    await api.singboxInstall();
    await api.singboxUninstall();
    await api.singboxDelete();
    await api.singboxRestart();
    await api.singboxStop();
    expect(fetchMock).toHaveBeenCalledTimes(12);
    expect(fetchMock).toHaveBeenCalledWith('/api/xray/delete', expect.any(Object));
    expect(fetchMock).toHaveBeenCalledWith('/api/xray/restart', expect.any(Object));
    expect(fetchMock).toHaveBeenCalledWith('/api/xray/stop', expect.any(Object));
    expect(fetchMock).toHaveBeenCalledWith('/api/singbox/delete', expect.any(Object));
    expect(fetchMock).toHaveBeenCalledWith('/api/singbox/restart', expect.any(Object));
    expect(fetchMock).toHaveBeenCalledWith('/api/singbox/stop', expect.any(Object));
    vi.unstubAllGlobals();
  });

  it('sends explicit confirmation for certificate management actions', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body))).toMatchObject({ confirm: true, allow_system_changes: true });
      return new Response(JSON.stringify({ status: 'ok', certificate: { id: 1 }, renewal: { checked: [], renewed: [], failed: [] } }), { status: 200, headers: { 'content-type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    await api.createCertificate(['example.com'], 'admin@example.com');
    await api.importCertificate({ fullchain: 'cert', private_key: 'key' });
    await api.applyCertificate(1, [2]);
    await api.renewDueCertificates();
    await api.deleteCertificate(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/certificates/1/delete', expect.objectContaining({ method: 'POST' }));
    expect(fetchMock).toHaveBeenCalledTimes(5);
    vi.unstubAllGlobals();
  });

  it('validates generated core configs with read-only requests', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.method).toBeUndefined();
      expect(init?.body).toBeUndefined();
      return new Response(JSON.stringify({ target: 'xray', valid: true, inbounds: 1 }), { status: 200, headers: { 'content-type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    await api.xrayValidate();
    await api.singboxValidate();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it('loads the dashboard summary from the new read-only API', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(init?.method).toBeUndefined();
      return new Response(JSON.stringify({ counts: {}, traffic: {}, protocols: {}, validation: {} }), { status: 200, headers: { 'content-type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    await api.dashboardSummary();
    expect(fetchMock).toHaveBeenCalledWith('/api/dashboard/summary', expect.any(Object));
    vi.unstubAllGlobals();
  });

  it('loads subscription links as text through the API boundary', async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('Accept')).toBe('text/plain');
      return new Response('vless://example\n', { status: 200, headers: { 'content-type': 'text/plain' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    await expect(api.subscriptionLink('client token')).resolves.toBe('vless://example');
    expect(fetchMock).toHaveBeenCalledWith('/sub/client%20token', expect.any(Object));
    vi.unstubAllGlobals();
  });

  it('keeps subscription text errors stable when the server returns plain text', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404, statusText: '', headers: { 'content-type': 'text/plain' } })),
    );
    await expect(api.subscriptionLink('missing')).rejects.toMatchObject({ status: 404, message: 'share_link_unavailable', code: 'share_link_unavailable' });
    vi.unstubAllGlobals();
  });

  it('preserves current location when redirecting to login after session expiry', async () => {
    window.history.replaceState({}, '', '/panel/routing?tab=rules#top');
    window.__MIGATE_BASE_PATH__ = '/panel';
    const assign = vi.fn();
    const originalLocation = window.location;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'unauthorized' } }), { status: 401, headers: { 'content-type': 'application/json' } })));
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, assign },
    });

    await expect(apiFetch('/api/routing-rules')).rejects.toMatchObject({ status: 401 });
    expect(assign).toHaveBeenCalledWith('/panel/login?next=%2Fpanel%2Frouting%3Ftab%3Drules%23top');

    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
    window.__MIGATE_BASE_PATH__ = undefined;
    vi.unstubAllGlobals();
  });

  it('does not redirect when login itself returns 401', async () => {
    const assign = vi.fn();
    const originalLocation = window.location;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'invalid_credentials', message: 'invalid_credentials' } }), { status: 401, headers: { 'content-type': 'application/json' } })));
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, assign },
    });

    await expect(api.login('admin', 'wrong')).rejects.toMatchObject({ status: 401, message: 'invalid_credentials' });
    expect(assign).not.toHaveBeenCalled();

    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
    vi.unstubAllGlobals();
  });

  it('redirects for protected API paths that merely share the login prefix', async () => {
    window.history.replaceState({}, '', '/panel/settings');
    window.__MIGATE_BASE_PATH__ = '/panel';
    const assign = vi.fn();
    const originalLocation = window.location;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'unauthorized' } }), { status: 401, headers: { 'content-type': 'application/json' } })));
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, assign },
    });

    await expect(apiFetch('/api/login-history')).rejects.toMatchObject({ status: 401 });
    expect(assign).toHaveBeenCalledWith('/panel/login?next=%2Fpanel%2Fsettings');

    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
    window.__MIGATE_BASE_PATH__ = undefined;
    vi.unstubAllGlobals();
  });
});
