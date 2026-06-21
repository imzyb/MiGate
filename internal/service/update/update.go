package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	runtimecmd "github.com/imzyb/MiGate/internal/runtime/command"
)

const DefaultCheckURL = "https://api.github.com/repos/imzyb/MiGate/releases/latest"
const DefaultLogPath = "/var/log/migate-update.log"
const DefaultStatusPath = "/var/lib/migate/update-status.json"
const stalePersistentStatusAfter = 15 * time.Minute
const installerPath = "/usr/local/bin/migate-install"
const installerCommand = "/usr/local/bin/migate-install --update --yes"

type Service struct {
	CheckURL   string
	LogPath    string
	StatusPath string
	Runner     runtimecmd.CommandRunner
	LookPath   func(string) (string, error)
	HTTPDo     func(*http.Request) (*http.Response, error)
	TestMode   bool
	State      *RuntimeState
	MaxLines   int
	Now        func() time.Time
	Geteuid    func() int
	Stat       func(string) (os.FileInfo, error)
	Getpid     func() int
	StartWait  time.Duration
}

type CheckResponse struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url"`
	ReleaseName     string `json:"release_name,omitempty"`
	Status          string `json:"status"`
	Message         string `json:"message,omitempty"`
}

type RuntimeStatus struct {
	Status         string    `json:"status"`
	CurrentVersion string    `json:"current_version,omitempty"`
	TargetVersion  string    `json:"target_version,omitempty"`
	Message        string    `json:"message,omitempty"`
	HealthCheck    string    `json:"health_check,omitempty"`
	RolledBack     bool      `json:"rolled_back,omitempty"`
	RollbackStatus string    `json:"rollback_status,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

type StartResponse struct {
	Status  string `json:"status"`
	Command string `json:"command"`
	Message string `json:"message"`
}

type LogsResponse struct {
	Logs string `json:"logs"`
	Path string `json:"path"`
}

type RuntimeState struct {
	mu      sync.Mutex
	running bool
	status  RuntimeStatus
}

type Error struct {
	Code   string
	Detail string
}

func (e Error) Error() string {
	if e.Detail != "" {
		return e.Code + ": " + e.Detail
	}
	return e.Code
}

func (e Error) ServiceCode() string {
	return e.Code
}

func (e Error) ServiceDetail() string {
	return e.Detail
}

func NewRuntimeState() *RuntimeState {
	return &RuntimeState{status: RuntimeStatus{Status: "idle", Message: "idle"}}
}

func (s Service) Check(ctx context.Context, currentVersion string) (CheckResponse, error) {
	current := normalizeMiGateVersionInput(currentVersion)
	result := CheckResponse{
		CurrentVersion:  current,
		LatestVersion:   "",
		UpdateAvailable: false,
		ReleaseURL:      "",
		Status:          "unknown",
	}
	if current == "dev" {
		result.Status = "dev"
		result.Message = "dev builds cannot be checked against releases"
		return result, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.checkURL(), nil)
	if err != nil {
		return CheckResponse{}, Error{Code: "update_check_failed", Detail: err.Error()}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MiGate-update-check")
	resp, err := s.httpDo()(req)
	if err != nil {
		return CheckResponse{}, Error{Code: "update_check_failed", Detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CheckResponse{}, Error{Code: "update_check_failed", Detail: resp.Status}
	}
	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return CheckResponse{}, Error{Code: "update_check_failed", Detail: err.Error()}
	}
	latest := strings.TrimSpace(release.TagName)
	result.LatestVersion = latest
	result.ReleaseURL = strings.TrimSpace(release.HTMLURL)
	result.ReleaseName = strings.TrimSpace(release.Name)
	result.Status = "ok"
	switch cmp, ok := CompareMiGateVersions(current, latest); {
	case !ok:
		result.Status = "unknown"
		result.Message = "无法解析当前版本或最新发布版本，已跳过自动升级判断"
	case cmp < 0:
		result.UpdateAvailable = true
	case cmp == 0:
		result.Message = "当前版本已是最新发布版本"
	default:
		result.Message = "当前版本高于最新发布版本，不会执行默认升级"
	}
	return result, nil
}

func (s Service) Status() RuntimeStatus {
	runtimeStatus := s.state().Snapshot()
	if isRuntimeStatusActive(runtimeStatus.Status) {
		return runtimeStatus
	}
	persistent, err := s.readPersistentStatus()
	if err == nil && strings.TrimSpace(persistent.Status) != "" {
		if isRuntimeStatusTerminal(runtimeStatus.Status) && isRuntimeStatusActive(persistent.Status) {
			return runtimeStatus
		}
		if isStalePersistentStatus(persistent, s.now()) {
			persistent.Status = "failed"
			persistent.Message = "上次更新状态长时间未完成，已标记为失败；可重新发起更新"
			persistent.UpdatedAt = s.now().UTC()
		}
		return persistent
	}
	return runtimeStatus
}

func (s Service) Logs(lines string) LogsResponse {
	clamped := s.ClampLogLines(lines)
	logs, err := s.readLogs(clamped)
	if err != nil {
		logs = fmt.Sprintf("无法读取更新日志：%v", err)
	}
	return LogsResponse{Logs: logs, Path: s.logPath()}
}

func (s Service) Start(ctx context.Context, currentVersion string) (StartResponse, RuntimeStatus, bool, error) {
	current := normalizeMiGateVersionInput(currentVersion)
	if err := ctx.Err(); err != nil {
		return StartResponse{}, RuntimeStatus{}, false, Error{Code: "request_canceled", Detail: err.Error()}
	}
	if !s.TestMode {
		if err := s.ValidateUpdaterAvailable(); err != nil {
			return StartResponse{}, RuntimeStatus{}, false, Error{Code: "updater_unavailable", Detail: err.Error()}
		}
	}
	if err := ctx.Err(); err != nil {
		return StartResponse{}, RuntimeStatus{}, false, Error{Code: "request_canceled", Detail: err.Error()}
	}
	status, started := s.state().Start(current, s.now())
	if !started {
		return StartResponse{}, status, false, nil
	}
	_ = s.appendLog(fmt.Sprintf("\n[%s] WebUI requested MiGate update from %s\n", s.now().Format(time.RFC3339), current))
	response := StartResponse{Status: "updating", Command: installerCommand, Message: status.Message}
	if s.TestMode {
		s.state().Finish("started", "update command accepted in test mode", s.now())
		return response, status, true, nil
	}
	updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	go s.runUpdateCommand(updateCtx, cancel)
	return response, status, true, nil
}

func (s Service) ValidateUpdaterAvailable() error {
	if s.geteuid() != 0 {
		return fmt.Errorf("MiGate service must run as root to start the updater")
	}
	if _, err := s.lookPath()("systemd-run"); err != nil {
		return fmt.Errorf("systemd-run not found: %w", err)
	}
	if _, err := s.stat()("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd is not available: %w", err)
	}
	if info, err := s.stat()(installerPath); err != nil {
		return fmt.Errorf("%s not available: %w", installerPath, err)
	} else if info.IsDir() || info.Mode()&0111 == 0 {
		return fmt.Errorf("%s is not executable", installerPath)
	}
	return nil
}

func (s Service) ClampLogLines(value string) string {
	if value == "" {
		return "120"
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return "120"
	}
	maxLines := s.MaxLines
	if maxLines <= 0 {
		maxLines = 2000
	}
	if n > maxLines {
		return strconv.Itoa(maxLines)
	}
	return strconv.Itoa(n)
}

func NormalizeMiGateVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "MiGate version:")
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	return version
}

var semanticVersionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`)

func CompareMiGateVersions(current, latest string) (int, bool) {
	currentParts, ok := parseMiGateVersion(current)
	if !ok {
		return 0, false
	}
	latestParts, ok := parseMiGateVersion(latest)
	if !ok {
		return 0, false
	}
	for i := range currentParts {
		if latestParts[i] > currentParts[i] {
			return -1, true
		}
		if latestParts[i] < currentParts[i] {
			return 1, true
		}
	}
	return 0, true
}

func parseMiGateVersion(version string) ([3]int, bool) {
	var parts [3]int
	normalized := NormalizeMiGateVersion(version)
	matches := semanticVersionPattern.FindStringSubmatch(normalized)
	if matches == nil {
		return parts, false
	}
	for i := range parts {
		value, err := strconv.Atoi(matches[i+1])
		if err != nil {
			return parts, false
		}
		parts[i] = value
	}
	return parts, true
}

func (s Service) readLogs(lines string) (string, error) {
	if _, err := s.stat()(s.logPath()); err == nil {
		out, err := s.runner().RunOutput(context.Background(), "tail", "-n", lines, s.logPath())
		if err == nil {
			return string(out), nil
		}
		if journalOut, journalErr := s.readJournalLogs(lines); journalErr == nil {
			return journalOut, nil
		}
		return string(out), err
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return s.readJournalLogs(lines)
}

func (s Service) readJournalLogs(lines string) (string, error) {
	if _, err := s.lookPath()("journalctl"); err == nil {
		out, journalErr := s.runner().RunOutput(context.Background(), "journalctl", "-u", "migate-update", "-u", "migate-update-*", "-n", lines, "--no-pager", "-o", "short-iso")
		if journalErr == nil {
			return string(out), nil
		}
		return string(out), journalErr
	}
	return "", fmt.Errorf("%s 不存在，且 journalctl 不可用", s.logPath())
}

func (s Service) appendLog(entry string) error {
	f, err := os.OpenFile(s.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}

func (s Service) runUpdateCommand(ctx context.Context, cancel context.CancelFunc) {
	if cancel != nil {
		defer cancel()
	}
	time.Sleep(s.startWait())
	unit := fmt.Sprintf("migate-update-%d-%d", s.getpid(), s.now().UnixNano())
	logPath := s.logPath()
	out, err := s.runner().RunOutput(ctx, "systemd-run", "--wait", "--unit="+unit, "--property=Type=oneshot", "--property=User=root", "--property=TimeoutSec=300", "--property=StandardOutput=append:"+logPath, "--property=StandardError=append:"+logPath, installerPath, "--update", "--yes")
	if len(out) > 0 {
		_ = s.appendLog(string(out))
	}
	if err != nil {
		message := strings.TrimSpace(string(out))
		if recent, logErr := s.readLogs("20"); logErr == nil && strings.TrimSpace(recent) != "" {
			message = strings.TrimSpace(recent)
		}
		if message == "" {
			message = err.Error()
		} else {
			message = err.Error() + ": " + lastNonEmptyLine(message)
		}
		_ = s.appendLog(fmt.Sprintf("[%s] update failed: %s\n", s.now().Format(time.RFC3339), message))
		s.state().Finish("failed", message, s.now())
		return
	}
	s.state().Finish("completed", "update command completed; MiGate may restart if a new version was installed", s.now())
}

func (s Service) state() *RuntimeState {
	if s.State != nil {
		return s.State
	}
	return defaultState
}

func (s Service) runner() runtimecmd.CommandRunner {
	if s.Runner != nil {
		return s.Runner
	}
	return runtimecmd.NewRealCommandRunner(5 * time.Minute)
}

func (s Service) lookPath() func(string) (string, error) {
	if s.LookPath != nil {
		return s.LookPath
	}
	return runtimecmd.LookPath
}

func (s Service) httpDo() func(*http.Request) (*http.Response, error) {
	if s.HTTPDo != nil {
		return s.HTTPDo
	}
	return http.DefaultClient.Do
}

func (s Service) checkURL() string {
	if strings.TrimSpace(s.CheckURL) != "" {
		return strings.TrimSpace(s.CheckURL)
	}
	return DefaultCheckURL
}

func (s Service) logPath() string {
	if strings.TrimSpace(s.LogPath) != "" {
		return strings.TrimSpace(s.LogPath)
	}
	return DefaultLogPath
}

func (s Service) statusPath() string {
	if strings.TrimSpace(s.StatusPath) != "" {
		return strings.TrimSpace(s.StatusPath)
	}
	return DefaultStatusPath
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Service) geteuid() int {
	if s.Geteuid != nil {
		return s.Geteuid()
	}
	return os.Geteuid()
}

func (s Service) stat() func(string) (os.FileInfo, error) {
	if s.Stat != nil {
		return s.Stat
	}
	return os.Stat
}

func (s Service) getpid() int {
	if s.Getpid != nil {
		return s.Getpid()
	}
	return os.Getpid()
}

func (s Service) startWait() time.Duration {
	if s.StartWait > 0 {
		return s.StartWait
	}
	return 500 * time.Millisecond
}

func normalizeMiGateVersionInput(version string) string {
	current := strings.TrimSpace(version)
	if current == "" {
		return "dev"
	}
	return current
}

func lastNonEmptyLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}

func (s Service) readPersistentStatus() (RuntimeStatus, error) {
	data, err := os.ReadFile(s.statusPath())
	if err != nil {
		return RuntimeStatus{}, err
	}
	var status RuntimeStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return RuntimeStatus{}, err
	}
	return status, nil
}

func isRuntimeStatusActive(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending", "running", "updating", "downloading", "installing", "restarting":
		return true
	default:
		return false
	}
}

func isRuntimeStatusTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "started", "failed", "completed":
		return true
	default:
		return false
	}
}

func isStalePersistentStatus(status RuntimeStatus, now time.Time) bool {
	if !isRuntimeStatusActive(status.Status) {
		return false
	}
	if status.UpdatedAt.IsZero() {
		return true
	}
	return now.UTC().Sub(status.UpdatedAt.UTC()) > stalePersistentStatusAfter
}

func (s *RuntimeState) Start(current string, now time.Time) (RuntimeStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return s.status, false
	}
	now = now.UTC()
	s.running = true
	s.status = RuntimeStatus{
		Status:         "updating",
		CurrentVersion: current,
		Message:        "update command accepted",
		StartedAt:      now,
		UpdatedAt:      now,
	}
	return s.status, true
}

func (s *RuntimeState) Finish(status, message string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	s.status.Status = status
	s.status.Message = message
	s.status.UpdatedAt = now.UTC()
}

func (s *RuntimeState) Snapshot() RuntimeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

var defaultState = NewRuntimeState()
