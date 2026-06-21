import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { LockKeyhole } from 'lucide-react';
import { basePath } from '../api/client';
import { api } from '../api/endpoints';
import type { Session } from '../api/types';
import { Field, useToast } from '../components/ui';
import { useI18n } from '../lib/i18n';
import { refreshSessionState } from '../lib/queryInvalidation';
import { z } from '../lib/zod';

const schema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

type FormValues = z.infer<typeof schema>;

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const { text } = useI18n();
  const session = useQuery({ queryKey: ['session'], queryFn: api.session });
  const form = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { username: 'admin', password: '' } });
  const target = redirectTarget(location);
  const login = useMutation({
    mutationFn: (values: FormValues) => api.login(values.username, values.password),
    onSuccess: (_data, values) => {
      queryClient.setQueryData<Session>(['session'], {
        auth_enabled: true,
        authenticated: true,
        username: values.username,
        revoked: false,
        default_password: false,
      });
      navigate(target, { replace: true });
      refreshSessionState(queryClient);
    },
    onError: () => showToast(text('登录失败，请检查用户名或密码'), 'error'),
  });

  useEffect(() => {
    if (session.data?.authenticated || session.data?.auth_enabled === false) {
      navigate(target, { replace: true });
    }
  }, [navigate, session.data?.auth_enabled, session.data?.authenticated, target]);

  return (
    <div className="login-screen">
      <form className="login-panel" onSubmit={form.handleSubmit((values) => login.mutate(values))}>
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg bg-panel-text text-panel-bg">
            <LockKeyhole className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">MiGate</h1>
            <p className="text-sm text-panel-muted">{text('面板登录')}</p>
          </div>
        </div>
        {session.isError ? <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{text('会话检查失败，请直接登录或刷新页面。')}</div> : null}
        <div className="grid gap-4">
          <Field label={text('用户名')}>
            <input {...form.register('username')} autoComplete="username" />
          </Field>
          <Field label={text('密码')}>
            <input {...form.register('password')} type="password" autoComplete="current-password" />
          </Field>
          <button className="btn primary h-10" disabled={login.isPending}>
            {login.isPending ? text('登录中...') : text('登录')}
          </button>
        </div>
      </form>
    </div>
  );
}

export function redirectTarget(location: ReturnType<typeof useLocation>): string {
  const next = new URLSearchParams(location.search).get('next');
  if (next && next.startsWith('/') && !next.startsWith('//')) {
    const normalizedNext = stripRuntimeBasePath(next);
    if (isSafeAppPath(normalizedNext) && !isLoginPath(normalizedNext)) return normalizedNext;
  }
  const from = typeof location.state === 'object' && location.state && 'from' in location.state ? (location.state as { from?: { pathname?: string; search?: string } }).from : undefined;
  const path = from?.pathname || '/';
  const search = from?.search || '';
  if (isLoginPath(path)) return '/';
  return `${path}${search}`;
}

export function stripRuntimeBasePath(path: string): string {
  const base = basePath();
  if (base && path === base) return '/';
  if (base && path.startsWith(`${base}/`)) return path.slice(base.length) || '/';
  return path;
}

function isLoginPath(path: string): boolean {
  return path === '/login' || path.startsWith('/login/');
}

function isSafeAppPath(path: string): boolean {
  return path.startsWith('/') && !path.startsWith('//');
}
