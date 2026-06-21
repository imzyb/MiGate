package web

import (
	"context"
	"net/http"
	"time"
)

func ExposeForTestCoreInstallHandler(core string, runner func(script string) ([]byte, error)) http.HandlerFunc {
	return coreInstallHandler(core, runner)
}

type Socks5PoolCacheForTest = socks5PoolCache

func ProxyPoolListHandlerForTest(cache *Socks5PoolCacheForTest, poolURL string, protocol string, w http.ResponseWriter, r *http.Request) {
	proxyPoolListHandler(func(ctx context.Context) ([]socks5PoolProxy, time.Time, string, error) {
		return cachedProxyPool(ctx, cache, poolURL, poolURL, protocol)
	}, w, r)
}

func SetProxyPoolAfterSingleflightForTest(cache *Socks5PoolCacheForTest, hook func()) {
	cache.afterSingleflightForTest = hook
}
