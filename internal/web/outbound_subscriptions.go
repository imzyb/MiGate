package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	outsub "github.com/imzyb/MiGate/internal/subscription"
)

type SubscriptionFetcher interface {
	Fetch(ctx context.Context, rawURL string, allowPrivate bool) ([]byte, error)
}

type OutboundSubscriptionRefreshResult struct {
	SubscriptionID int64  `json:"subscription_id"`
	Count          int    `json:"count"`
	SkippedCount   int    `json:"skipped_count"`
	LastFetchedAt  string `json:"last_fetched_at,omitempty"`
	Error          string `json:"error,omitempty"`
	ConfigChanged  bool   `json:"config_changed"`
}

func outboundSubscriptionsHandler(cfg *routerConfig) http.HandlerFunc {
	store := cfg.store
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			subs, err := store.ListOutboundSubscriptions(r.Context())
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_outbound_subscriptions_failed")
				return
			}
			writeJSON(w, http.StatusOK, subs)
		case http.MethodPost:
			if strings.TrimSuffix(r.URL.Path, "/") == "/api/outbound-subscriptions/refresh" {
				refreshAllOutboundSubscriptionsHandler(cfg, w, r)
				return
			}
			if strings.TrimSuffix(r.URL.Path, "/") == "/api/outbound-subscriptions/preview" {
				previewOutboundSubscriptionHandler(cfg, w, r)
				return
			}
			if strings.TrimSuffix(r.URL.Path, "/") == "/api/outbound-subscriptions/reorder" {
				reorderOutboundSubscriptionsHandler(cfg, w, r)
				return
			}
			var params db.CreateOutboundSubscriptionParams
			if err := decodeJSONBody(r, &params); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json")
				return
			}
			sub, err := store.CreateOutboundSubscription(r.Context(), params)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "create_outbound_subscription_failed")
				return
			}
			writeJSON(w, http.StatusCreated, map[string]interface{}{"subscription": sub})
		default:
			methodNotAllowed(w)
		}
	}
}

func outboundSubscriptionChildrenHandler(cfg *routerConfig) http.HandlerFunc {
	store := cfg.store
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/outbound-subscriptions/"), "/")
		switch path {
		case "refresh":
			if r.Method != http.MethodPost {
				methodNotAllowed(w)
				return
			}
			refreshAllOutboundSubscriptionsHandler(cfg, w, r)
			return
		case "preview":
			if r.Method != http.MethodPost {
				methodNotAllowed(w)
				return
			}
			previewOutboundSubscriptionHandler(cfg, w, r)
			return
		case "reorder":
			if r.Method != http.MethodPost {
				methodNotAllowed(w)
				return
			}
			reorderOutboundSubscriptionsHandler(cfg, w, r)
			return
		}
		refresh := strings.HasSuffix(path, "/refresh")
		if refresh {
			path = strings.TrimSuffix(path, "/refresh")
		}
		id, err := strconv.ParseInt(strings.TrimSpace(path), 10, 64)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_id")
			return
		}
		if refresh {
			if r.Method != http.MethodPost {
				methodNotAllowed(w)
				return
			}
			refreshOneOutboundSubscriptionHandler(cfg, id, w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var params db.UpdateOutboundSubscriptionParams
			if err := decodeJSONBody(r, &params); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json")
				return
			}
			previous, previousFound, err := store.GetOutboundSubscription(r.Context(), id)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "get_outbound_subscription_failed")
				return
			}
			includeXray, includeSingbox, err := xrayAndSingboxForAllOutbounds(r.Context(), store)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_failed")
				return
			}
			before := captureCoreGeneratedHashes(r.Context(), cfg, includeXray, includeSingbox)
			sub, err := store.UpdateOutboundSubscription(r.Context(), id, params)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					writeJSONError(w, http.StatusNotFound, "not_found")
				} else {
					writeJSONError(w, http.StatusBadRequest, "update_outbound_subscription_failed")
				}
				return
			}
			needsRefresh := previousFound && !previous.Enabled && sub.Enabled
			writeCoreWriteResultForHashes(w, r, cfg, http.StatusOK, map[string]interface{}{"subscription": sub, "needs_refresh": needsRefresh}, before, includeXray, includeSingbox, includeXray, includeSingbox)
		case http.MethodDelete:
			includeXray, includeSingbox, err := xrayAndSingboxForAllOutbounds(r.Context(), store)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_failed")
				return
			}
			before := captureCoreGeneratedHashes(r.Context(), cfg, includeXray, includeSingbox)
			if err := store.DeleteOutboundSubscription(r.Context(), id); err != nil {
				if strings.Contains(err.Error(), "not found") {
					writeJSONError(w, http.StatusNotFound, "not_found")
				} else {
					writeJSONError(w, http.StatusInternalServerError, "delete_outbound_subscription_failed")
				}
				return
			}
			writeCoreWriteResultForHashes(w, r, cfg, http.StatusOK, map[string]interface{}{"status": "deleted"}, before, includeXray, includeSingbox, includeXray, includeSingbox)
		default:
			methodNotAllowed(w)
		}
	}
}

func refreshOneOutboundSubscriptionHandler(cfg *routerConfig, id int64, w http.ResponseWriter, r *http.Request) {
	sub, found, err := cfg.store.GetOutboundSubscription(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "get_outbound_subscription_failed")
		return
	}
	if !found {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	if !sub.Enabled {
		writeJSONError(w, http.StatusBadGateway, "refresh_outbound_subscription_failed", map[string]interface{}{"detail": "subscription is disabled"})
		return
	}
	type refreshResponse struct {
		status  int
		payload map[string]interface{}
	}
	resultCh := make(chan refreshResponse, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		status, payload := runOneOutboundSubscriptionRefresh(ctx, cfg, id)
		resultCh <- refreshResponse{status: status, payload: payload}
	}()
	select {
	case result := <-resultCh:
		writeJSON(w, result.status, result.payload)
	case <-time.After(100 * time.Millisecond):
		writeJSON(w, http.StatusAccepted, map[string]interface{}{"status": "queued", "subscription_id": id})
	}
}

func runOneOutboundSubscriptionRefresh(ctx context.Context, cfg *routerConfig, id int64) (int, map[string]interface{}) {
	includeXray, includeSingbox, err := xrayAndSingboxForAllOutbounds(ctx, cfg.store)
	if err != nil {
		return http.StatusInternalServerError, map[string]interface{}{"error": "list_failed"}
	}
	before := captureCoreGeneratedHashes(ctx, cfg, includeXray, includeSingbox)
	result, markXray, markSingbox, err := refreshOutboundSubscription(ctx, cfg.store, id)
	if err != nil {
		return http.StatusBadGateway, map[string]interface{}{"error": "refresh_outbound_subscription_failed", "detail": err.Error()}
	}
	includeXray, includeSingbox = includeExistingPendingCores(ctx, cfg, markXray, markSingbox)
	payload := map[string]interface{}{"result": result}
	populateCoreWriteResultForHashes(ctx, cfg, payload, before, markXray, markSingbox, includeXray, includeSingbox)
	return http.StatusOK, payload
}

func refreshAllOutboundSubscriptionsHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	subs, err := cfg.store.ListOutboundSubscriptions(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_outbound_subscriptions_failed")
		return
	}
	results := []map[string]interface{}{}
	markXray := false
	markSingbox := false
	includeXray, includeSingbox, err := xrayAndSingboxForAllOutbounds(r.Context(), cfg.store)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_failed")
		return
	}
	before := captureCoreGeneratedHashes(r.Context(), cfg, includeXray, includeSingbox)
	for _, sub := range subs {
		if !sub.Enabled {
			continue
		}
		result, xrayChanged, singboxChanged, err := refreshOutboundSubscription(r.Context(), cfg.store, sub.ID)
		if err != nil {
			results = append(results, map[string]interface{}{"subscription_id": sub.ID, "error": err.Error()})
			continue
		}
		results = append(results, result)
		markXray = markXray || xrayChanged
		markSingbox = markSingbox || singboxChanged
	}
	includeXray, includeSingbox = includeExistingPendingCores(r.Context(), cfg, markXray, markSingbox)
	writeCoreWriteResultForHashes(w, r, cfg, http.StatusOK, map[string]interface{}{"results": results}, before, markXray, markSingbox, includeXray, includeSingbox)
}

func previewOutboundSubscriptionHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL          string `json:"url"`
		AllowPrivate bool   `json:"allow_private"`
		Body         string `json:"body"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	var body []byte
	var err error
	if strings.TrimSpace(req.Body) != "" {
		body = []byte(req.Body)
	} else {
		body, err = outsub.HTTPFetcher{}.Fetch(r.Context(), req.URL, req.AllowPrivate)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, "fetch_outbound_subscription_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
	}
	result, err := outsub.ParseLinks(outsub.DecodeBody(body))
	if err != nil {
		if len(result.Nodes) == 0 && len(result.Skipped) > 0 {
			writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": result.Nodes, "count": 0, "skipped_count": len(result.Skipped), "skipped": result.Skipped})
			return
		}
		writeJSONError(w, http.StatusBadRequest, "parse_outbound_subscription_failed", map[string]interface{}{"detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": result.Nodes, "count": len(result.Nodes), "skipped_count": len(result.Skipped), "skipped": result.Skipped})
}

func reorderOutboundSubscriptionsHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := decodeJSONBody(r, &req); err != nil || len(req.IDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_payload")
		return
	}
	includeXray, includeSingbox, err := xrayAndSingboxForAllOutbounds(r.Context(), cfg.store)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_failed")
		return
	}
	before := captureCoreGeneratedHashes(r.Context(), cfg, includeXray, includeSingbox)
	if err := cfg.store.ReorderOutboundSubscriptions(r.Context(), req.IDs); err != nil {
		writeJSONError(w, http.StatusBadRequest, "reorder_outbound_subscriptions_failed")
		return
	}
	writeCoreWriteResultForHashes(w, r, cfg, http.StatusOK, map[string]interface{}{"status": "reordered"}, before, includeXray, includeSingbox, includeXray, includeSingbox)
}

func refreshOutboundSubscription(ctx context.Context, store Store, id int64) (map[string]interface{}, bool, bool, error) {
	result, includeXray, includeSingbox, err := RefreshOutboundSubscription(ctx, store, nil, id)
	if result == nil {
		return nil, includeXray, includeSingbox, err
	}
	payload := map[string]interface{}{
		"subscription_id": result.SubscriptionID,
		"count":           result.Count,
		"skipped_count":   result.SkippedCount,
		"last_fetched_at": result.LastFetchedAt,
		"config_changed":  result.ConfigChanged,
	}
	if result.Error != "" {
		payload["error"] = result.Error
	}
	return payload, includeXray, includeSingbox, err
}

func RefreshOutboundSubscription(ctx context.Context, store Store, fetcher SubscriptionFetcher, id int64) (*OutboundSubscriptionRefreshResult, bool, bool, error) {
	sub, ok, err := store.GetOutboundSubscription(ctx, id)
	if err != nil {
		return nil, false, false, err
	}
	if !ok {
		return nil, false, false, fmt.Errorf("outbound subscription not found: %d", id)
	}
	if !sub.Enabled {
		return nil, false, false, fmt.Errorf("outbound subscription disabled: %d", id)
	}
	if fetcher == nil {
		fetcher = outsub.HTTPFetcher{}
	}
	body, err := fetcher.Fetch(ctx, sub.URL, sub.AllowPrivate)
	if err != nil {
		_ = store.MarkOutboundSubscriptionFetch(ctx, id, time.Now(), err.Error(), nil)
		return nil, false, false, err
	}
	parsed, err := outsub.ParseLinks(outsub.DecodeBody(body))
	if err != nil {
		_ = store.MarkOutboundSubscriptionFetch(ctx, id, time.Now(), err.Error(), nil)
		return nil, false, false, err
	}
	existing, err := store.ListOutbounds(ctx)
	if err != nil {
		return nil, false, false, err
	}
	beforeFingerprint := outboundCoreConfigFingerprint(existing)
	nodes, identities := outsub.Materialize(id, parsed.Nodes, existing, sub.TagPrefix)
	scope, err := loadCoreInboundScope(ctx, store)
	if err != nil {
		return nil, false, false, err
	}
	materialized, err := store.MaterializeSubscriptionOutbounds(ctx, id, nodes, identities)
	if err != nil {
		_ = store.MarkOutboundSubscriptionFetch(ctx, id, time.Now(), err.Error(), nil)
		return nil, false, false, err
	}
	configChanged := beforeFingerprint != outboundCoreConfigFingerprint(materialized)
	lastFetchedAt := time.Now().UTC().Format(time.RFC3339)
	lastErr := ""
	if len(parsed.Skipped) > 0 {
		lastErr = fmt.Sprintf("部分节点跳过：%d 个", len(parsed.Skipped))
		if err := store.MarkOutboundSubscriptionFetch(ctx, id, time.Now(), lastErr, identities); err != nil {
			log.Printf("outbound subscription refresh: failed to record skipped summary for %d: %v", id, err)
		}
	}
	includeXray := configChanged && scope.hasCore(db.CoreXray)
	includeSingbox := configChanged && scope.hasCore(db.CoreSingbox)
	return &OutboundSubscriptionRefreshResult{SubscriptionID: id, Count: len(nodes), SkippedCount: len(parsed.Skipped), LastFetchedAt: lastFetchedAt, Error: lastErr, ConfigChanged: configChanged}, includeXray, includeSingbox, nil
}

type outboundCoreConfigSnapshot struct {
	ID           int64  `json:"id"`
	Tag          string `json:"tag"`
	Protocol     string `json:"protocol"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Enabled      bool   `json:"enabled"`
	Sort         int    `json:"sort"`
	SettingsJSON string `json:"settings_json"`
}

func outboundCoreConfigFingerprint(outbounds []db.Outbound) string {
	snapshots := make([]outboundCoreConfigSnapshot, 0, len(outbounds))
	for _, outbound := range outbounds {
		snapshots = append(snapshots, outboundCoreConfigSnapshot{
			ID:           outbound.ID,
			Tag:          strings.TrimSpace(outbound.Tag),
			Protocol:     db.NormalizeOutboundProtocol(outbound.Protocol),
			Address:      strings.TrimSpace(outbound.Address),
			Port:         outbound.Port,
			Username:     strings.TrimSpace(outbound.Username),
			Password:     outbound.Password,
			Enabled:      outbound.Enabled,
			Sort:         outbound.Sort,
			SettingsJSON: strings.TrimSpace(outbound.SettingsJSON),
		})
	}
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].Sort != snapshots[j].Sort {
			return snapshots[i].Sort < snapshots[j].Sort
		}
		return snapshots[i].ID < snapshots[j].ID
	})
	data, _ := json.Marshal(snapshots)
	return string(data)
}

func xrayAndSingboxForAllOutbounds(ctx context.Context, store Store) (bool, bool, error) {
	scope, err := loadCoreInboundScope(ctx, store)
	if err != nil {
		return false, false, err
	}
	return scope.hasCore(db.CoreXray), scope.hasCore(db.CoreSingbox), nil
}
