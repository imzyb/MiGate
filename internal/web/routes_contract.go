package web

import "net/http"

type AuthPolicy string

const (
	AuthPublic   AuthPolicy = "public"
	AuthRequired AuthPolicy = "required"
)

type CSRFPolicy string

const (
	CSRFNotRequired CSRFPolicy = "not_required"
	CSRFRequired    CSRFPolicy = "required"
)

type RouteContract struct {
	Method  string
	Path    string
	Auth    AuthPolicy
	CSRF    CSRFPolicy
	Handler string
}

type Route struct {
	RouteContract
	Build func(*routeDeps) http.HandlerFunc
}

type routeDeps struct {
	cfg          *routerConfig
	trafficCache *trafficViewCache
	coreCache    *coreStatusCache
}

func (r Route) register(mux *http.ServeMux, deps *routeDeps) {
	mux.HandleFunc(r.Path, r.Build(deps))
}

func registerAPIRoutes(mux *http.ServeMux, cfg *routerConfig, trafficCache *trafficViewCache, coreCache *coreStatusCache) {
	deps := &routeDeps{cfg: cfg, trafficCache: trafficCache, coreCache: coreCache}
	registered := map[string]bool{}
	for _, route := range routeTable() {
		if registered[route.Path] {
			continue
		}
		route.register(mux, deps)
		registered[route.Path] = true
	}
}

func RouteContracts() []RouteContract {
	routes := routeTable()
	contracts := make([]RouteContract, 0, len(routes))
	for _, route := range routes {
		contracts = append(contracts, route.RouteContract)
	}
	return contracts
}

func routeTable() []Route {
	route := func(method, path string, auth AuthPolicy, csrf CSRFPolicy, handler string, build func(*routeDeps) http.HandlerFunc) Route {
		return Route{RouteContract: RouteContract{Method: method, Path: path, Auth: auth, CSRF: csrf, Handler: handler}, Build: build}
	}
	return []Route{
		route(http.MethodPost, "/api/login", AuthPublic, CSRFRequired, "loginHandler", func(d *routeDeps) http.HandlerFunc { return loginHandler(d.cfg) }),
		route(http.MethodPost, "/api/logout", AuthRequired, CSRFRequired, "logoutHandler", func(d *routeDeps) http.HandlerFunc { return logoutHandler(d.cfg) }),
		route(http.MethodGet, "/api/session", AuthPublic, CSRFNotRequired, "sessionHandler", func(d *routeDeps) http.HandlerFunc { return sessionHandler(d.cfg) }),
		route(http.MethodGet, "/api/sessions", AuthRequired, CSRFNotRequired, "sessionsListHandler", func(d *routeDeps) http.HandlerFunc { return sessionsListHandler(d.cfg) }),
		route(http.MethodDelete, "/api/sessions/", AuthRequired, CSRFRequired, "sessionRevokeHandler", func(d *routeDeps) http.HandlerFunc { return sessionRevokeHandler(d.cfg) }),
		route(http.MethodGet, "/api/health", AuthPublic, CSRFNotRequired, "healthHandler", func(*routeDeps) http.HandlerFunc { return healthHandler }),
		route(http.MethodGet, "/api/inbound-capabilities", AuthRequired, CSRFNotRequired, "inboundCapabilitiesHandler", func(*routeDeps) http.HandlerFunc { return inboundCapabilitiesHandler }),
		route(http.MethodPost, "/api/reality/keypair", AuthRequired, CSRFRequired, "realityKeypairHandler", func(*routeDeps) http.HandlerFunc { return realityKeypairHandler }),
		route(http.MethodGet, "/api/inbounds", AuthRequired, CSRFNotRequired, "inboundsHandler", func(d *routeDeps) http.HandlerFunc { return inboundsHandler(d.cfg) }),
		route(http.MethodPost, "/api/inbounds", AuthRequired, CSRFRequired, "inboundsHandler", func(d *routeDeps) http.HandlerFunc { return inboundsHandler(d.cfg) }),
		route(http.MethodPut, "/api/inbounds/", AuthRequired, CSRFRequired, "inboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return inboundChildrenHandler(d.cfg) }),
		route(http.MethodPatch, "/api/inbounds/", AuthRequired, CSRFRequired, "inboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return inboundChildrenHandler(d.cfg) }),
		route(http.MethodDelete, "/api/inbounds/", AuthRequired, CSRFRequired, "inboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return inboundChildrenHandler(d.cfg) }),
		route(http.MethodPost, "/api/inbounds/", AuthRequired, CSRFRequired, "inboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return inboundChildrenHandler(d.cfg) }),
		route(http.MethodGet, "/api/outbounds", AuthRequired, CSRFNotRequired, "outboundsHandler", func(d *routeDeps) http.HandlerFunc { return outboundsHandler(d.cfg) }),
		route(http.MethodPost, "/api/outbounds", AuthRequired, CSRFRequired, "outboundsHandler", func(d *routeDeps) http.HandlerFunc { return outboundsHandler(d.cfg) }),
		route(http.MethodGet, "/api/outbounds/", AuthRequired, CSRFNotRequired, "outboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return outboundChildrenHandler(d.cfg) }),
		route(http.MethodPut, "/api/outbounds/", AuthRequired, CSRFRequired, "outboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return outboundChildrenHandler(d.cfg) }),
		route(http.MethodDelete, "/api/outbounds/", AuthRequired, CSRFRequired, "outboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return outboundChildrenHandler(d.cfg) }),
		route(http.MethodPost, "/api/outbounds/", AuthRequired, CSRFRequired, "outboundChildrenHandler", func(d *routeDeps) http.HandlerFunc { return outboundChildrenHandler(d.cfg) }),
		route(http.MethodGet, "/api/outbound-subscriptions", AuthRequired, CSRFNotRequired, "outboundSubscriptionsHandler", func(d *routeDeps) http.HandlerFunc { return outboundSubscriptionsHandler(d.cfg) }),
		route(http.MethodPost, "/api/outbound-subscriptions", AuthRequired, CSRFRequired, "outboundSubscriptionsHandler", func(d *routeDeps) http.HandlerFunc { return outboundSubscriptionsHandler(d.cfg) }),
		route(http.MethodPut, "/api/outbound-subscriptions/", AuthRequired, CSRFRequired, "outboundSubscriptionChildrenHandler", func(d *routeDeps) http.HandlerFunc { return outboundSubscriptionChildrenHandler(d.cfg) }),
		route(http.MethodDelete, "/api/outbound-subscriptions/", AuthRequired, CSRFRequired, "outboundSubscriptionChildrenHandler", func(d *routeDeps) http.HandlerFunc { return outboundSubscriptionChildrenHandler(d.cfg) }),
		route(http.MethodPost, "/api/outbound-subscriptions/", AuthRequired, CSRFRequired, "outboundSubscriptionChildrenHandler", func(d *routeDeps) http.HandlerFunc { return outboundSubscriptionChildrenHandler(d.cfg) }),
		route(http.MethodGet, "/api/routing-rules", AuthRequired, CSRFNotRequired, "routingRulesHandler", func(d *routeDeps) http.HandlerFunc { return routingRulesHandler(d.cfg) }),
		route(http.MethodPost, "/api/routing-rules", AuthRequired, CSRFRequired, "routingRulesHandler", func(d *routeDeps) http.HandlerFunc { return routingRulesHandler(d.cfg) }),
		route(http.MethodGet, "/api/routing-rules/", AuthRequired, CSRFNotRequired, "routingRuleChildrenHandler", func(d *routeDeps) http.HandlerFunc { return routingRuleChildrenHandler(d.cfg) }),
		route(http.MethodPut, "/api/routing-rules/", AuthRequired, CSRFRequired, "routingRuleChildrenHandler", func(d *routeDeps) http.HandlerFunc { return routingRuleChildrenHandler(d.cfg) }),
		route(http.MethodDelete, "/api/routing-rules/", AuthRequired, CSRFRequired, "routingRuleChildrenHandler", func(d *routeDeps) http.HandlerFunc { return routingRuleChildrenHandler(d.cfg) }),
		route(http.MethodPost, "/api/routing-rules/", AuthRequired, CSRFRequired, "routingRuleChildrenHandler", func(d *routeDeps) http.HandlerFunc { return routingRuleChildrenHandler(d.cfg) }),
		route(http.MethodGet, "/api/stats", AuthRequired, CSRFNotRequired, "statsHandler", func(d *routeDeps) http.HandlerFunc { return statsHandler(d.cfg.store, d.cfg.statsClient) }),
		route(http.MethodGet, "/api/traffic/summary", AuthRequired, CSRFNotRequired, "trafficSummaryHandler", func(d *routeDeps) http.HandlerFunc { return trafficSummaryHandler(d.cfg.store, d.trafficCache) }),
		route(http.MethodGet, "/api/traffic/inbounds", AuthRequired, CSRFNotRequired, "trafficInboundsHandler", func(d *routeDeps) http.HandlerFunc { return trafficInboundsHandler(d.cfg.store, d.trafficCache) }),
		route(http.MethodGet, "/api/traffic/clients", AuthRequired, CSRFNotRequired, "trafficClientsHandler", func(d *routeDeps) http.HandlerFunc { return trafficClientsHandler(d.cfg.store, d.trafficCache) }),
		route(http.MethodGet, "/api/traffic/series", AuthRequired, CSRFNotRequired, "trafficSeriesHandler", func(d *routeDeps) http.HandlerFunc { return trafficSeriesHandler(d.cfg.store) }),
		route(http.MethodGet, "/api/dashboard/summary", AuthRequired, CSRFNotRequired, "dashboardSummaryHandler", func(d *routeDeps) http.HandlerFunc { return dashboardSummaryHandler(d.cfg) }),
		route(http.MethodGet, "/api/system/resources", AuthRequired, CSRFNotRequired, "systemResourcesHandler", func(*routeDeps) http.HandlerFunc { return systemResourcesHandler() }),
		route(http.MethodGet, "/api/xray/status", AuthRequired, CSRFNotRequired, "xrayStatusHandler", func(d *routeDeps) http.HandlerFunc { return d.coreCache.wrap("xray-status", xrayStatusHandler(d.cfg)) }),
		route(http.MethodGet, "/api/xray/config", AuthRequired, CSRFNotRequired, "xrayConfigHandler", func(d *routeDeps) http.HandlerFunc { return xrayConfigHandler(d.cfg) }),
		route(http.MethodGet, "/api/xray/config/preview", AuthRequired, CSRFNotRequired, "xrayConfigPreviewHandler", func(d *routeDeps) http.HandlerFunc { return xrayConfigPreviewHandler(d.cfg) }),
		route(http.MethodGet, "/api/xray/validate", AuthRequired, CSRFNotRequired, "xrayValidateHandler", func(d *routeDeps) http.HandlerFunc { return xrayValidateHandler(d.cfg) }),
		route(http.MethodGet, "/api/xray/diagnostics", AuthRequired, CSRFNotRequired, "xrayDiagnosticsHandler", func(d *routeDeps) http.HandlerFunc { return xrayDiagnosticsHandler(d.cfg) }),
		route(http.MethodPost, "/api/xray/apply", AuthRequired, CSRFRequired, "xrayApplyHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"xray-status", "xray-version", "singbox-status", "singbox-version"}, xrayApplyHandler(d.cfg))
		}),
		route(http.MethodPost, "/api/xray/install", AuthRequired, CSRFRequired, "coreInstallHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"xray-status", "xray-version"}, coreInstallHandler("xray", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/xray/uninstall", AuthRequired, CSRFRequired, "coreUninstallHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"xray-status", "xray-version"}, coreUninstallHandler("xray", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/xray/delete", AuthRequired, CSRFRequired, "coreDeleteHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"xray-status", "xray-version"}, coreDeleteHandler("xray", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/xray/restart", AuthRequired, CSRFRequired, "coreServiceControlHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"xray-status"}, coreServiceControlHandler("xray", "restart", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/xray/stop", AuthRequired, CSRFRequired, "coreServiceControlHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"xray-status"}, coreServiceControlHandler("xray", "stop", d.cfg.coreScriptRunner))
		}),
		route(http.MethodGet, "/api/xray/logs", AuthRequired, CSRFNotRequired, "xrayLogsHandler", func(*routeDeps) http.HandlerFunc { return xrayLogsHandler() }),
		route(http.MethodGet, "/api/xray/version", AuthRequired, CSRFNotRequired, "xrayVersionHandler", func(d *routeDeps) http.HandlerFunc {
			return d.coreCache.wrap("xray-version", xrayVersionHandler(d.cfg.xrayController))
		}),
		route(http.MethodGet, "/api/singbox/status", AuthRequired, CSRFNotRequired, "singboxStatusHandler", func(d *routeDeps) http.HandlerFunc {
			return d.coreCache.wrap("singbox-status", singboxStatusHandler(d.cfg))
		}),
		route(http.MethodGet, "/api/singbox/diagnostics", AuthRequired, CSRFNotRequired, "singboxDiagnosticsHandler", func(d *routeDeps) http.HandlerFunc { return singboxDiagnosticsHandler(d.cfg) }),
		route(http.MethodPost, "/api/singbox/apply", AuthRequired, CSRFRequired, "singboxApplyHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"singbox-status", "singbox-version"}, singboxApplyHandler(d.cfg))
		}),
		route(http.MethodGet, "/api/singbox/validate", AuthRequired, CSRFNotRequired, "singboxValidateHandler", func(d *routeDeps) http.HandlerFunc { return singboxValidateHandler(d.cfg) }),
		route(http.MethodPost, "/api/singbox/install", AuthRequired, CSRFRequired, "coreInstallHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"singbox-status", "singbox-version"}, coreInstallHandler("singbox", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/singbox/uninstall", AuthRequired, CSRFRequired, "coreUninstallHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"singbox-status", "singbox-version"}, coreUninstallHandler("singbox", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/singbox/delete", AuthRequired, CSRFRequired, "coreDeleteHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"singbox-status", "singbox-version"}, coreDeleteHandler("singbox", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/singbox/restart", AuthRequired, CSRFRequired, "coreServiceControlHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"singbox-status"}, coreServiceControlHandler("singbox", "restart", d.cfg.coreScriptRunner))
		}),
		route(http.MethodPost, "/api/singbox/stop", AuthRequired, CSRFRequired, "coreServiceControlHandler", func(d *routeDeps) http.HandlerFunc {
			return invalidateCoreCacheAfter(d.coreCache, []string{"singbox-status"}, coreServiceControlHandler("singbox", "stop", d.cfg.coreScriptRunner))
		}),
		route(http.MethodGet, "/api/singbox/config", AuthRequired, CSRFNotRequired, "singboxConfigHandler", func(d *routeDeps) http.HandlerFunc { return singboxConfigHandler(d.cfg) }),
		route(http.MethodGet, "/api/singbox/config/preview", AuthRequired, CSRFNotRequired, "singboxConfigPreviewHandler", func(d *routeDeps) http.HandlerFunc { return singboxConfigPreviewHandler(d.cfg) }),
		route(http.MethodGet, "/api/singbox/version", AuthRequired, CSRFNotRequired, "singboxVersionHandler", func(d *routeDeps) http.HandlerFunc {
			return d.coreCache.wrap("singbox-version", singboxVersionHandler())
		}),
		route(http.MethodGet, "/api/singbox/logs", AuthRequired, CSRFNotRequired, "singboxLogsHandler", func(*routeDeps) http.HandlerFunc { return singboxLogsHandler() }),
		route(http.MethodGet, "/api/cert/status", AuthRequired, CSRFNotRequired, "certStatusHandler", func(d *routeDeps) http.HandlerFunc { return certStatusHandler(d.cfg) }),
		route(http.MethodPost, "/api/cert/issue", AuthRequired, CSRFRequired, "certIssueHandler", func(d *routeDeps) http.HandlerFunc { return certIssueHandler(d.cfg) }),
		route(http.MethodGet, "/api/certificates", AuthRequired, CSRFNotRequired, "certificatesHandler", func(d *routeDeps) http.HandlerFunc { return certificatesHandler(d.cfg) }),
		route(http.MethodPost, "/api/certificates", AuthRequired, CSRFRequired, "certificatesHandler", func(d *routeDeps) http.HandlerFunc { return certificatesHandler(d.cfg) }),
		route(http.MethodGet, "/api/certificates/", AuthRequired, CSRFNotRequired, "certificateChildrenHandler", func(d *routeDeps) http.HandlerFunc { return certificateChildrenHandler(d.cfg) }),
		route(http.MethodPost, "/api/certificates/", AuthRequired, CSRFRequired, "certificateChildrenHandler", func(d *routeDeps) http.HandlerFunc { return certificateChildrenHandler(d.cfg) }),
		route(http.MethodGet, "/api/settings", AuthRequired, CSRFNotRequired, "settingsHandler", func(d *routeDeps) http.HandlerFunc { return settingsHandler(d.cfg) }),
		route(http.MethodPut, "/api/settings", AuthRequired, CSRFRequired, "settingsHandler", func(d *routeDeps) http.HandlerFunc { return settingsHandler(d.cfg) }),
		route(http.MethodPost, "/api/restart", AuthRequired, CSRFRequired, "restartHandler", func(*routeDeps) http.HandlerFunc { return restartHandler() }),
		route(http.MethodGet, "/api/service/status", AuthRequired, CSRFNotRequired, "serviceStatusHandler", func(*routeDeps) http.HandlerFunc { return serviceStatusHandler() }),
		route(http.MethodGet, "/api/version", AuthRequired, CSRFNotRequired, "versionHandler", func(d *routeDeps) http.HandlerFunc { return versionHandler(d.cfg.version) }),
		route(http.MethodGet, "/api/update/check", AuthRequired, CSRFNotRequired, "updateCheckHandler", func(d *routeDeps) http.HandlerFunc { return updateCheckHandler(d.cfg) }),
		route(http.MethodPost, "/api/update", AuthRequired, CSRFRequired, "updateHandler", func(d *routeDeps) http.HandlerFunc { return updateHandler(d.cfg) }),
		route(http.MethodGet, "/api/update/status", AuthRequired, CSRFNotRequired, "updateStatusHandler", func(d *routeDeps) http.HandlerFunc { return updateStatusHandler(d.cfg) }),
		route(http.MethodGet, "/api/update/logs", AuthRequired, CSRFNotRequired, "updateLogsHandler", func(d *routeDeps) http.HandlerFunc { return updateLogsHandler(d.cfg) }),
	}
}
