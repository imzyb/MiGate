export class ApiError extends Error {
  status: number;
  payload: unknown;
  code?: string;
  detail?: string;
  fields?: Record<string, unknown>;
  details?: unknown;

  constructor(status: number, message: string, payload: unknown, options: { code?: string; detail?: string; fields?: Record<string, unknown>; details?: unknown } = {}) {
    super(message);
    this.status = status;
    this.payload = payload;
    this.code = options.code;
    this.detail = options.detail;
    this.fields = options.fields;
    this.details = options.details ?? options.fields ?? options.detail;
  }
}

export interface APIErrorBody {
  error?: {
    code?: string;
    message?: string;
    detail?: string;
    fields?: Record<string, unknown>;
  };
  status?: number;
}

export function basePath(): string {
  if (window.__MIGATE_BASE_PATH__) return window.__MIGATE_BASE_PATH__;
  const path = window.location.pathname;
  const known = ['/login', '/assets/', '/api/', '/sub/'];
  for (const marker of known) {
    const index = path.indexOf(marker);
    if (index > 0) return path.slice(0, index);
  }
  if (path === '/' || path === '/login') return '';
  if (path === '/panel') return '/panel';
  if (path.endsWith('/login')) return path.slice(0, -'/login'.length);
  const spaRoutes = ['/inbounds', '/outbounds', '/routing', '/topology', '/core', '/xray', '/singbox', '/settings'];
  for (const route of spaRoutes) {
    if (path === route) return '';
    if (path.endsWith(route)) return path.slice(0, -route.length);
    const nestedIndex = path.indexOf(`${route}/`);
    if (nestedIndex > 0) return path.slice(0, nestedIndex);
  }
  const firstSegment = path.match(/^\/[^/]+/)?.[0] || '';
  return firstSegment === path ? '' : firstSegment;
}

export function appPath(path: string): string {
  const base = basePath();
  const clean = path.startsWith('/') ? path : `/${path}`;
  return `${base}${clean}` || '/';
}

async function parseResponse(response: Response) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return response.json();
  return response.text();
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const hasBody = init.body !== undefined && init.body !== null;
  if (hasBody && !headers.has('Content-Type') && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');
  const response = await fetch(appPath(path), {
    credentials: 'same-origin',
    ...init,
    headers,
  });
  const payload = await parseResponse(response).catch(() => null);
  if (response.status === 401 && shouldRedirectOnUnauthorized(path)) {
    const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    window.location.assign(`${appPath('/login')}?next=${encodeURIComponent(current)}`);
  }
  if (!response.ok) {
    const standardError = readStandardError(payload);
    throw new ApiError(response.status, standardError.message || standardError.code || response.statusText || 'request_failed', payload, {
      code: standardError.code,
      detail: standardError.detail,
      fields: standardError.fields,
    });
  }
  return payload as T;
}

export async function apiText(path: string, init: RequestInit = {}, fallbackErrorCode = 'request_failed'): Promise<string> {
  const headers = new Headers(init.headers);
  if (!headers.has('Accept')) headers.set('Accept', 'text/plain');
  try {
    const response = await apiFetch<string>(path, { ...init, headers });
    return String(response || '');
  } catch (error) {
    if (error instanceof ApiError && !error.code) {
      throw new ApiError(error.status, fallbackErrorCode, error.payload, { code: fallbackErrorCode });
    }
    throw error;
  }
}

function readStandardError(payload: unknown): { message?: string; code?: string; detail?: string; fields?: Record<string, unknown> } {
  const payloadObject = payload && typeof payload === 'object' ? (payload as APIErrorBody) : null;
  const errorObject = payloadObject && payloadObject.error && typeof payloadObject.error === 'object' ? payloadObject.error : null;
  if (!errorObject) return {};
  return {
    message: errorObject.message ? String(errorObject.message) : undefined,
    code: errorObject.code ? String(errorObject.code) : undefined,
    detail: errorObject.detail ? String(errorObject.detail) : undefined,
    fields: errorObject.fields && typeof errorObject.fields === 'object' ? errorObject.fields : undefined,
  };
}

export function getAPIErrorMessage(error: unknown, fallback = 'request_failed'): string {
  if (error instanceof ApiError) return error.message || error.code || fallback;
  return fallback;
}

export const formatAPIError = getAPIErrorMessage;

function shouldRedirectOnUnauthorized(path: string): boolean {
  const endpoint = normalizeAPIPath(path);
  return endpoint !== '/api/session' && endpoint !== '/api/login';
}

function normalizeAPIPath(path: string): string {
  const withoutHash = path.split('#', 1)[0];
  const withoutQuery = withoutHash.split('?', 1)[0];
  if (withoutQuery.length > 1) return withoutQuery.replace(/\/+$/, '');
  return withoutQuery || '/';
}

export function get<T>(path: string) {
  return apiFetch<T>(path);
}

export function post<T>(path: string, body?: unknown) {
  return apiFetch<T>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function patch<T>(path: string, body: unknown) {
  return apiFetch<T>(path, { method: 'PATCH', body: JSON.stringify(body) });
}

export function put<T>(path: string, body: unknown) {
  return apiFetch<T>(path, { method: 'PUT', body: JSON.stringify(body) });
}

export function del<T>(path: string) {
  return apiFetch<T>(path, { method: 'DELETE' });
}
