import { describe, expect, it, vi } from 'vitest';
import {
  refreshQueries,
  refreshQuery,
  refreshCertificateOperationDependencies,
  refreshSessionDependencies,
  refreshSessionState,
  refreshSettingsDependencies,
  refreshTopologyDependencies,
  refreshUpdateDependencies,
} from './queryInvalidation';

describe('query invalidation helpers', () => {
  it('refreshes every topology dependency after topology-affecting writes', () => {
    const queryClient = { invalidateQueries: vi.fn() };

    refreshTopologyDependencies(queryClient as never);

    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['inbounds'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['inbounds', 'traffic'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['outbounds'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['routing-rules'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['dashboard-summary'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['traffic-summary'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['traffic-inbounds'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['traffic-clients'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['traffic-series'] });
  });

  it('centralizes explicit query refresh calls', () => {
    const first = { refetch: vi.fn() };
    const second = { refetch: vi.fn() };

    refreshQuery(first);
    refreshQueries([first, second]);

    expect(first.refetch).toHaveBeenCalledTimes(2);
    expect(second.refetch).toHaveBeenCalledTimes(1);
  });

  it('centralizes settings page invalidation groups', () => {
    const queryClient = { invalidateQueries: vi.fn() };

    refreshSettingsDependencies(queryClient as never);
    refreshCertificateOperationDependencies(queryClient as never);
    refreshUpdateDependencies(queryClient as never);
    refreshSessionDependencies(queryClient as never);

    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['settings'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['cert-status'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['certificate-operations'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['update-status'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['update-logs'] });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['sessions'] });
  });

  it('centralizes current session refresh after login state changes', () => {
    const queryClient = { invalidateQueries: vi.fn() };

    refreshSessionState(queryClient as never);

    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({ queryKey: ['session'] });
  });
});
