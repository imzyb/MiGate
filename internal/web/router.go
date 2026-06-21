package web

import (
	"net/http"
	"strings"
	"time"
)

func NewRouter(options ...Option) http.Handler {
	cfg := routerConfig{
		xrayController:   defaultXrayController{},
		singboxRuntime:   defaultSingboxRuntime{},
		socks5PoolURL:    defaultSocks5PoolURL,
		httpPoolURL:      defaultHTTPPoolURL,
		httpsPoolURL:     defaultHTTPSPoolURL,
		updateCheckURL:   defaultUpdateCheckURL,
		loginLimiter:     newLoginLimiter(defaultLoginFailureLimit, defaultLoginCooldown),
		coreScriptRunner: runCoreScript,
		singboxApplier:   tryApplySingboxWithRuntime,
	}
	for _, option := range options {
		option(&cfg)
	}
	mux := http.NewServeMux()
	trafficCache := newTrafficViewCache(2 * time.Second)
	coreCache := newCoreStatusCache(3 * time.Second)
	mux.Handle("/assets/", staticAssetsHandler())
	mux.Handle("/favicon.svg", staticRootAssetHandler("/favicon.svg"))
	mux.Handle("/favicon.ico", staticRootAssetHandler("/favicon.ico"))
	mux.HandleFunc("/login", loginPageHandler(&cfg))
	registerAPIRoutes(mux, &cfg, trafficCache, coreCache)
	mux.HandleFunc("/sub/", subscriptionHandler(&cfg))
	mux.HandleFunc("/", spaHandler(cfg.basePath))
	handler := csrfMiddleware(mux, &cfg)
	handler = authMiddleware(handler, &cfg)
	handler = securityHeadersMiddleware(handler, &cfg)
	if cfg.basePath != "" {
		return basePathMiddleware(handler, cfg.basePath)
	}
	return handler
}

func normalizeBasePath(basePath string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" || basePath == "/" {
		return ""
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return strings.TrimRight(basePath, "/")
}

func basePathMiddleware(next http.Handler, basePath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isRootStaticAsset(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == basePath {
			target := basePath + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
		if r.URL.Path != basePath && !strings.HasPrefix(r.URL.Path, basePath+"/") {
			http.NotFound(w, r)
			return
		}
		cloned := r.Clone(r.Context())
		cloned.URL.Path = strings.TrimPrefix(r.URL.Path, basePath)
		if cloned.URL.Path == "" {
			cloned.URL.Path = "/"
		}
		cloned.URL.RawPath = ""
		next.ServeHTTP(w, cloned)
	})
}

func isRootStaticAsset(path string) bool {
	return path == "/favicon.svg" || path == "/favicon.ico"
}

func invalidateCoreCacheAfter(cache *coreStatusCache, keys []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r)
		if r.Method == http.MethodPost {
			cache.invalidate(keys...)
		}
	}
}
