import type { QueryClient } from '@tanstack/react-query';

type RefreshableQuery = {
  refetch: () => unknown;
};

export function refreshTopologyDependencies(queryClient: QueryClient) {
  queryClient.invalidateQueries({ queryKey: ['inbounds'] });
  queryClient.invalidateQueries({ queryKey: ['inbounds', 'traffic'] });
  queryClient.invalidateQueries({ queryKey: ['outbounds'] });
  queryClient.invalidateQueries({ queryKey: ['routing-rules'] });
  queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
  queryClient.invalidateQueries({ queryKey: ['traffic-summary'] });
  queryClient.invalidateQueries({ queryKey: ['traffic-inbounds'] });
  queryClient.invalidateQueries({ queryKey: ['traffic-clients'] });
  queryClient.invalidateQueries({ queryKey: ['traffic-series'] });
}

export function refreshOutboundDependencies(queryClient: QueryClient) {
  refreshTopologyDependencies(queryClient);
  queryClient.invalidateQueries({ queryKey: ['outbound-subscriptions'] });
}

function invalidateQueryKeys(queryClient: QueryClient, keys: string[][]) {
  keys.forEach((queryKey) => queryClient.invalidateQueries({ queryKey }));
}

export function refreshSettingsDependencies(queryClient: QueryClient) {
  invalidateQueryKeys(queryClient, [['settings'], ['cert-status'], ['certificates'], ['certificate-inbounds']]);
}

export function refreshCertificateApplyDependencies(queryClient: QueryClient) {
  invalidateQueryKeys(queryClient, [['cert-status'], ['certificates'], ['certificate-inbounds'], ['inbounds'], ['dashboard-summary']]);
}

export function refreshCertificateOperationDependencies(queryClient: QueryClient) {
  invalidateQueryKeys(queryClient, [['certificate-operations']]);
}

export function refreshUpdateDependencies(queryClient: QueryClient) {
  invalidateQueryKeys(queryClient, [['update-status'], ['update-logs']]);
}

export function refreshSessionDependencies(queryClient: QueryClient) {
  invalidateQueryKeys(queryClient, [['sessions']]);
}

export function refreshSessionState(queryClient: QueryClient) {
  invalidateQueryKeys(queryClient, [['session']]);
}

export function refetchTopologyDependencies(queryClient: QueryClient) {
  return Promise.all([
    queryClient.refetchQueries({ queryKey: ['inbounds'] }),
    queryClient.refetchQueries({ queryKey: ['outbounds'] }),
    queryClient.refetchQueries({ queryKey: ['routing-rules'] }),
  ]);
}

export function refreshQuery(query: RefreshableQuery) {
  return query['refetch']();
}

export function refreshQueries(queries: RefreshableQuery[]) {
  queries.forEach(refreshQuery);
}
