package web

import (
	"net/http"

	updatesvc "github.com/imzyb/MiGate/internal/service/update"
)

const defaultUpdateCheckURL = updatesvc.DefaultCheckURL

func versionHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if version == "" {
			version = "dev"
		}
		writeJSON(w, http.StatusOK, map[string]string{"version": version})
	}
}

func updateCheckHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		result, err := updateService(cfg.version, cfg.updateCheckURL, cfg.updateStatusPath).Check(r.Context(), cfg.version)
		if err != nil {
			writeServiceError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func updateStatusHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, updateService("", "", cfg.updateStatusPath).Status())
	}
}

func updateLogsHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, updateService("", "", cfg.updateStatusPath).Logs(r.URL.Query().Get("lines")))
	}
}

func updateHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if _, ok := decodeCoreActionPayload(w, r); !ok {
			return
		}
		service := updateService(cfg.version, cfg.updateCheckURL, "")
		check, err := service.Check(r.Context(), cfg.version)
		if err != nil {
			writeServiceError(w, http.StatusBadGateway, err)
			return
		}
		if !check.UpdateAvailable {
			message := check.Message
			if message == "" {
				message = "当前版本不可执行默认 latest 升级"
			}
			WriteError(w, http.StatusConflict, APIError{
				Code:    "update_not_available",
				Message: message,
				Fields:  map[string]interface{}{"status": check.Status},
			}, nil)
			return
		}
		response, status, started, err := service.Start(r.Context(), cfg.version)
		if err != nil {
			writeServiceError(w, http.StatusServiceUnavailable, err)
			return
		}
		if !started {
			writeJSON(w, http.StatusConflict, status)
			return
		}
		writeJSON(w, http.StatusOK, response)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func updateService(version, checkURL, statusPath string) updatesvc.Service {
	_ = version
	return updatesvc.Service{
		CheckURL:   checkURL,
		StatusPath: statusPath,
		TestMode:   runningUnderGoTest(),
		MaxLines:   maxXrayLogLines,
	}
}
