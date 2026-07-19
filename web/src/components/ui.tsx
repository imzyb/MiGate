import { Children, createContext, isValidElement, useCallback, useContext, useState } from 'react';
import { CheckCircle2, Info, Loader2, X, XCircle } from 'lucide-react';
import clsx from 'clsx';
import { useI18n } from '../lib/i18n';

type ToastAction = { label: string; onClick: () => void };
type Toast = { id: number; title: string; tone: 'success' | 'error' | 'info'; action?: ToastAction };

const ToastContext = createContext<{ showToast: (title: string, tone?: Toast['tone'], action?: ToastAction) => void } | null>(null);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const { text } = useI18n();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const showToast = useCallback((title: string, tone: Toast['tone'] = 'info', action?: ToastAction) => {
    const id = Date.now() + Math.random();
    setToasts((items) => [...items, { id, title, tone, action }]);
    window.setTimeout(() => setToasts((items) => items.filter((item) => item.id !== id)), 3200);
  }, []);
  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div className="fixed right-4 top-4 z-50 grid w-[min(360px,calc(100vw-2rem))] gap-2">
        {toasts.map((toast) => (
          <div key={toast.id} className="flex items-center gap-3 rounded-lg border border-panel-line bg-panel-surface px-4 py-3 text-sm shadow-panel">
            {toast.tone === 'error' ? <XCircle className="h-4 w-4 text-red-500" /> : toast.tone === 'info' ? <Info className="h-4 w-4 text-sky-500" /> : <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
            <span className="min-w-0 flex-1 text-panel-text">{text(toast.title)}</span>
            {toast.action ? (
              <button
                className="btn secondary compact"
                onClick={() => {
                  setToasts((items) => items.filter((item) => item.id !== toast.id));
                  toast.action?.onClick();
                }}
              >
                {text(toast.action.label)}
              </button>
            ) : null}
            <button className="icon-button h-7 w-7" onClick={() => setToasts((items) => items.filter((item) => item.id !== toast.id))}>
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside ToastProvider');
  return ctx;
}

type ConfirmState = {
  title: string;
  description?: string;
  tone?: 'danger' | 'normal';
  resolve: (value: boolean) => void;
};

const ConfirmContext = createContext<(input: Omit<ConfirmState, 'resolve'>) => Promise<boolean>>(() => Promise.resolve(false));

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const { t, text } = useI18n();
  const [state, setState] = useState<ConfirmState | null>(null);
  const confirm = useCallback((input: Omit<ConfirmState, 'resolve'>) => {
    return new Promise<boolean>((resolve) => setState({ ...input, resolve }));
  }, []);
  const close = (value: boolean) => {
    state?.resolve(value);
    setState(null);
  };
  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {state ? (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-panel max-w-md">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-base font-semibold text-panel-text">{text(state.title)}</h2>
                {state.description ? <p className="mt-2 text-sm leading-6 text-panel-muted">{text(state.description)}</p> : null}
              </div>
              <button className="icon-button" onClick={() => close(false)}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button className="btn secondary" onClick={() => close(false)}>
                {t('cancel')}
              </button>
              <button className={clsx('btn', state.tone === 'danger' ? 'danger' : 'primary')} onClick={() => close(true)}>
                {t('confirm')}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  return useContext(ConfirmContext);
}

export function Modal({
  open,
  title,
  children,
  onClose,
  footer,
  panelClassName,
}: {
  open: boolean;
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  footer?: React.ReactNode;
  panelClassName?: string;
}) {
  const { text } = useI18n();
  if (!open) return null;
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className={clsx('modal-panel', panelClassName)}>
        <div className="flex items-center justify-between gap-4 border-b border-panel-line pb-3">
          <h2 className="text-base font-semibold text-panel-text">{text(title)}</h2>
          <button className="icon-button" onClick={onClose}>
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="mt-4">{children}</div>
        {footer ? <div className="mt-5 flex justify-end gap-2 border-t border-panel-line pt-4">{footer}</div> : null}
      </div>
    </div>
  );
}

export function EmptyState({ title, description, action }: { title: string; description?: string; action?: React.ReactNode }) {
  const { text } = useI18n();
  return (
    <div className="rounded-lg border border-dashed border-panel-line bg-panel-soft px-5 py-10 text-center">
      <div className="text-sm font-semibold text-panel-text">{text(title)}</div>
      {description ? <div className="mx-auto mt-2 max-w-md text-sm leading-6 text-panel-muted">{text(description)}</div> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function LoadingBlock({ label }: { label?: string }) {
  const { t, text } = useI18n();
  return <div className="rounded-lg border border-panel-line bg-panel-surface p-6 text-sm text-panel-muted shadow-panel">{label ? text(label) : t('loading')}</div>;
}

export function Field({ label, children, help }: { label: string; children: React.ReactNode; help?: string }) {
  const { text } = useI18n();
  return (
    <label className="grid gap-1.5 text-sm">
      <span className="font-medium text-panel-text">{text(label)}</span>
      {children}
      {help ? <span className="text-xs leading-5 text-panel-muted">{text(help)}</span> : null}
    </label>
  );
}

export function FieldError({ message }: { message?: string }) {
  const { text } = useI18n();
  if (!message) return null;
  return <span className="text-xs leading-5 text-red-600">{text(message)}</span>;
}

export function StatusBadge({ enabled, children }: { enabled: boolean; children?: React.ReactNode }) {
  const { t } = useI18n();
  return <span className={clsx('status-badge', enabled ? 'status-on' : 'status-off')}>{children || t(enabled ? 'enabled' : 'disabled')}</span>;
}

export function toggleButtonClass(enabled: boolean) {
  return clsx('icon-button toggle-button', enabled ? 'toggle-button-on' : 'toggle-button-off');
}

export function Card({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement> & { children: React.ReactNode }) {
  return <div className={clsx('rounded-lg border border-panel-line bg-panel-surface shadow-panel', className)} {...props}>{children}</div>;
}

export function SpinnerButton({
  loading,
  children,
  className,
  disabled,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean }) {
  return (
    <button className={className} disabled={disabled || loading} {...props}>
      {loading ? spinnerButtonLoadingContent(children) : children}
    </button>
  );
}

function spinnerButtonLoadingContent(children: React.ReactNode) {
  const spinner = <Loader2 key="spinner" className="h-4 w-4 animate-spin" aria-hidden="true" />;
  const items = Children.toArray(children);
  const iconIndex = items.findIndex(isReplaceableButtonIcon);

  if (iconIndex === -1) {
    return [spinner, ...items];
  }

  return items.map((item, index) => (index === iconIndex ? spinner : item));
}

function isReplaceableButtonIcon(child: React.ReactNode) {
  if (!isValidElement<{ className?: unknown }>(child) || typeof child.type === 'string') return false;
  const className = child.props.className;
  return typeof className === 'string' && /\bh-4\b/.test(className) && /\bw-4\b/.test(className);
}
