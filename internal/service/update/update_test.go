package update

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu          sync.Mutex
	enteredOnce sync.Once
	entered     chan struct{}
	release     chan struct{}
	calls       [][]string
	ctxs        []context.Context
	out         []byte
	err         error
}

func (r *fakeRunner) Run(ctx context.Context, name string, args ...string) error {
	r.mu.Lock()
	r.ctxs = append(r.ctxs, ctx)
	r.calls = append(r.calls, append([]string{name}, args...))
	err := r.err
	r.mu.Unlock()
	r.waitIfBlocked()
	return err
}

func (r *fakeRunner) RunOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	r.ctxs = append(r.ctxs, ctx)
	r.calls = append(r.calls, append([]string{name}, args...))
	out := append([]byte(nil), r.out...)
	err := r.err
	r.mu.Unlock()
	r.waitIfBlocked()
	return out, err
}

func (r *fakeRunner) waitIfBlocked() {
	if r.entered != nil {
		r.enteredOnce.Do(func() { close(r.entered) })
	}
	if r.release != nil {
		<-r.release
	}
}

func TestCheckReportsLatestRelease(t *testing.T) {
	service := Service{
		CheckURL: "https://example.test/latest",
		HTTPDo: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "https://example.test/latest" {
				t.Fatalf("unexpected URL %s", req.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v1.2.0","html_url":"https://example.test/release","name":"Release"}`)),
			}, nil
		},
	}
	result, err := service.Check(context.Background(), "v1.1.0")
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !result.UpdateAvailable || result.LatestVersion != "v1.2.0" || result.ReleaseURL != "https://example.test/release" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestCheckComparesSemanticVersions(t *testing.T) {
	tests := []struct {
		name            string
		current         string
		latest          string
		updateAvailable bool
		status          string
		messageContains string
	}{
		{
			name:            "current lower than latest",
			current:         "MiGate version: v1.2.2",
			latest:          "v1.2.3",
			updateAvailable: true,
			status:          "ok",
		},
		{
			name:            "current equals latest",
			current:         " 1.2.3 ",
			latest:          "v1.2.3",
			updateAvailable: false,
			status:          "ok",
			messageContains: "已是最新",
		},
		{
			name:            "current higher than latest",
			current:         "v1.3.5",
			latest:          "v1.3.3",
			updateAvailable: false,
			status:          "ok",
			messageContains: "高于最新发布版本",
		},
		{
			name:            "unparseable current",
			current:         "dev-build",
			latest:          "v1.3.3",
			updateAvailable: false,
			status:          "unknown",
			messageContains: "无法解析",
		},
		{
			name:            "unparseable latest",
			current:         "v1.3.3",
			latest:          "release",
			updateAvailable: false,
			status:          "unknown",
			messageContains: "无法解析",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := Service{
				CheckURL: "https://example.test/latest",
				HTTPDo: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Body:       io.NopCloser(strings.NewReader(`{"tag_name":"` + tt.latest + `","html_url":"https://example.test/release","name":"Release"}`)),
					}, nil
				},
			}
			result, err := service.Check(context.Background(), tt.current)
			if err != nil {
				t.Fatalf("Check returned error: %v", err)
			}
			if result.UpdateAvailable != tt.updateAvailable || result.Status != tt.status {
				t.Fatalf("unexpected result: %#v", result)
			}
			if tt.messageContains != "" && !strings.Contains(result.Message, tt.messageContains) {
				t.Fatalf("message %q missing %q", result.Message, tt.messageContains)
			}
		})
	}
}

func TestCompareMiGateVersionsNormalizesInputs(t *testing.T) {
	cmp, ok := CompareMiGateVersions(" MiGate version: v1.2.3 ", "1.2.4")
	if !ok || cmp >= 0 {
		t.Fatalf("expected latest to be newer, cmp=%d ok=%v", cmp, ok)
	}
	cmp, ok = CompareMiGateVersions("v1.2.3", " 1.2.3 ")
	if !ok || cmp != 0 {
		t.Fatalf("expected versions to be equal, cmp=%d ok=%v", cmp, ok)
	}
	if _, ok := CompareMiGateVersions("dev", "v1.2.3"); ok {
		t.Fatal("dev must not parse as a release version")
	}
}

func TestCheckSkipsDevBuilds(t *testing.T) {
	result, err := (Service{}).Check(context.Background(), "")
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if result.Status != "dev" || result.CurrentVersion != "dev" || result.UpdateAvailable {
		t.Fatalf("unexpected dev result: %#v", result)
	}
}

func TestStartUsesStateAndTestMode(t *testing.T) {
	state := NewRuntimeState()
	logPath := filepath.Join(t.TempDir(), "update.log")
	service := Service{
		State:    state,
		LogPath:  logPath,
		TestMode: true,
		Now:      func() time.Time { return time.Date(2026, 6, 19, 1, 2, 3, 0, time.UTC) },
	}
	response, _, started, err := service.Start(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if !started || response.Status != "updating" || response.Command != installerCommand {
		t.Fatalf("unexpected response started=%v response=%#v", started, response)
	}
	status := service.Status()
	if status.Status != "started" || status.CurrentVersion != "v1.0.0" {
		t.Fatalf("unexpected status: %#v", status)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "WebUI requested MiGate update from v1.0.0") {
		t.Fatalf("missing log entry: %s", string(data))
	}
}

func TestStartReturnsConflictStatusWhenRunning(t *testing.T) {
	state := NewRuntimeState()
	now := time.Now()
	if _, ok := state.Start("v1.0.0", now); !ok {
		t.Fatal("initial start failed")
	}
	_, status, started, err := (Service{State: state, TestMode: true, LogPath: filepath.Join(t.TempDir(), "update.log")}).Start(context.Background(), "v1.0.1")
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if started || status.CurrentVersion != "v1.0.0" {
		t.Fatalf("expected conflict status, started=%v status=%#v", started, status)
	}
}

func TestStartHonorsCanceledContextBeforeAccepting(t *testing.T) {
	state := NewRuntimeState()
	logPath := filepath.Join(t.TempDir(), "update.log")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, started, err := (Service{State: state, TestMode: true, LogPath: logPath}).Start(ctx, "v1.0.0")
	if started {
		t.Fatal("canceled request must not start update")
	}
	serviceErr, ok := err.(Error)
	if !ok || serviceErr.Code != "request_canceled" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if status := state.Snapshot(); status.Status != "idle" {
		t.Fatalf("state changed after canceled request: %#v", status)
	}
	if _, statErr := os.Stat(logPath); !os.IsNotExist(statErr) {
		t.Fatalf("canceled request must not write update log, stat err=%v", statErr)
	}
}

func TestStartHonorsContextCanceledDuringValidation(t *testing.T) {
	state := NewRuntimeState()
	logPath := filepath.Join(t.TempDir(), "update.log")
	runner := &fakeRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	service := Service{
		State:   state,
		LogPath: logPath,
		Runner:  runner,
		Geteuid: func() int { return 0 },
		LookPath: func(name string) (string, error) {
			cancel()
			return "/usr/bin/" + name, nil
		},
		Stat: func(path string) (os.FileInfo, error) {
			if path == installerPath {
				return fakeFileInfo{mode: 0755}, nil
			}
			if path == "/run/systemd/system" {
				return fakeFileInfo{mode: os.ModeDir | 0755}, nil
			}
			return nil, os.ErrNotExist
		},
	}
	_, _, started, err := service.Start(ctx, "v1.0.0")
	if started {
		t.Fatal("request canceled during validation must not start update")
	}
	serviceErr, ok := err.(Error)
	if !ok || serviceErr.Code != "request_canceled" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if status := state.Snapshot(); status.Status != "idle" {
		t.Fatalf("state changed after canceled request: %#v", status)
	}
	if _, statErr := os.Stat(logPath); !os.IsNotExist(statErr) {
		t.Fatalf("canceled request must not write update log, stat err=%v", statErr)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled request must not run updater, calls=%#v", runner.calls)
	}
}

func TestRunUpdateCommandUsesConfiguredLogPath(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "custom-update.log")
	runner := &fakeRunner{}
	service := Service{
		State:     NewRuntimeState(),
		LogPath:   logPath,
		Runner:    runner,
		StartWait: time.Nanosecond,
		Getpid:    func() int { return 123 },
		Now:       func() time.Time { return time.Unix(456, 0) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	service.runUpdateCommand(ctx, cancel)
	if len(runner.calls) != 1 {
		t.Fatalf("runner calls = %#v, want one systemd-run call", runner.calls)
	}
	args := strings.Join(runner.calls[0], "\n")
	for _, want := range []string{
		"--property=StandardOutput=append:" + logPath,
		"--property=StandardError=append:" + logPath,
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("systemd-run args missing %q: %#v", want, runner.calls[0])
		}
	}
}

func TestStartNonTestModeUsesBackgroundCommandContext(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "update.log")
	runner := &fakeRunner{entered: make(chan struct{}), release: make(chan struct{})}
	service := Service{
		State:     NewRuntimeState(),
		LogPath:   logPath,
		Runner:    runner,
		StartWait: time.Nanosecond,
		Geteuid:   func() int { return 0 },
		LookPath:  func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Stat: func(path string) (os.FileInfo, error) {
			if path == installerPath {
				return fakeFileInfo{mode: 0755}, nil
			}
			if path == "/run/systemd/system" {
				return fakeFileInfo{mode: os.ModeDir | 0755}, nil
			}
			return nil, os.ErrNotExist
		},
	}
	requestCtx, cancel := context.WithCancel(context.Background())
	response, _, started, err := service.Start(requestCtx, "v1.0.0")
	cancel()
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if !started || response.Status != "updating" {
		t.Fatalf("unexpected start result started=%v response=%#v", started, response)
	}
	select {
	case <-runner.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("runner was not called")
	}
	runner.mu.Lock()
	commandCtx := runner.ctxs[0]
	runner.mu.Unlock()
	defer close(runner.release)
	if commandCtx == nil {
		t.Fatal("runner context is nil")
	}
	if _, ok := commandCtx.Deadline(); !ok {
		t.Fatal("runner context must have an update timeout")
	}
	select {
	case <-commandCtx.Done():
		t.Fatal("runner context must not be canceled by request cancellation")
	default:
	}
}

func TestLogsReadsTailWhenLogExists(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "update.log")
	if err := os.WriteFile(logPath, []byte("one\ntwo\n"), 0644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	runner := &fakeRunner{out: []byte("two\n")}
	result := (Service{LogPath: logPath, Runner: runner}).Logs("1")
	if result.Logs != "two\n" || result.Path != logPath {
		t.Fatalf("unexpected logs: %#v", result)
	}
	if len(runner.calls) != 1 || runner.calls[0][0] != "tail" || runner.calls[0][2] != "1" {
		t.Fatalf("unexpected runner calls: %#v", runner.calls)
	}
}

func TestStatusReadsPersistentStatusWhenRuntimeIdle(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "update-status.json")
	if err := os.WriteFile(statusPath, []byte(`{
  "status": "failed",
  "current_version": "v1.0.0",
  "target_version": "v1.0.1",
  "message": "升级失败，已回滚，服务已恢复",
  "health_check": "systemctl is-active migate: active",
  "rolled_back": true,
  "rollback_status": "restored",
  "updated_at": "2026-06-19T01:02:03Z"
}`), 0640); err != nil {
		t.Fatalf("write status: %v", err)
	}
	status := (Service{State: NewRuntimeState(), StatusPath: statusPath}).Status()
	if status.Status != "failed" || !status.RolledBack || status.RollbackStatus != "restored" || status.TargetVersion != "v1.0.1" {
		t.Fatalf("unexpected persistent status: %#v", status)
	}
}

func TestStatusKeepsActiveRuntimeStatusAheadOfPersistentStatus(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "update-status.json")
	if err := os.WriteFile(statusPath, []byte(`{"status":"completed","message":"old"}`), 0640); err != nil {
		t.Fatalf("write status: %v", err)
	}
	state := NewRuntimeState()
	if _, ok := state.Start("v1.0.0", time.Now()); !ok {
		t.Fatal("start runtime status")
	}
	status := (Service{State: state, StatusPath: statusPath}).Status()
	if status.Status != "updating" || status.Message != "update command accepted" {
		t.Fatalf("runtime active status should win: %#v", status)
	}
}

func TestStatusKeepsRuntimeFailureAheadOfPersistentInProgress(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "update-status.json")
	if err := os.WriteFile(statusPath, []byte(`{
  "status": "downloading",
  "current_version": "v1.0.0",
  "target_version": "v1.0.1",
  "message": "downloading",
  "updated_at": "2026-06-19T01:02:03Z"
}`), 0640); err != nil {
		t.Fatalf("write status: %v", err)
	}
	state := NewRuntimeState()
	if _, ok := state.Start("v1.0.0", time.Now()); !ok {
		t.Fatal("start runtime status")
	}
	state.Finish("failed", "systemd-run failed before installer completed", time.Now())
	status := (Service{State: state, StatusPath: statusPath}).Status()
	if status.Status != "failed" || !strings.Contains(status.Message, "systemd-run failed") {
		t.Fatalf("runtime failure should win over persistent in-progress: %#v", status)
	}
}

func TestStatusMarksStalePersistentInProgressAsFailed(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "update-status.json")
	if err := os.WriteFile(statusPath, []byte(`{
  "status": "installing",
  "current_version": "v1.0.0",
  "target_version": "v1.0.1",
  "message": "still installing",
  "updated_at": "2026-06-19T01:00:00Z"
}`), 0640); err != nil {
		t.Fatalf("write status: %v", err)
	}
	status := (Service{
		State:      NewRuntimeState(),
		StatusPath: statusPath,
		Now:        func() time.Time { return time.Date(2026, 6, 19, 1, 16, 1, 0, time.UTC) },
	}).Status()
	if status.Status != "failed" || !strings.Contains(status.Message, "长时间未完成") {
		t.Fatalf("stale in-progress status should be failed: %#v", status)
	}
}

func TestStatusKeepsFreshPersistentInProgress(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "update-status.json")
	if err := os.WriteFile(statusPath, []byte(`{
  "status": "restarting",
  "current_version": "v1.0.0",
  "target_version": "v1.0.1",
  "message": "restarting",
  "updated_at": "2026-06-19T01:10:00Z"
}`), 0640); err != nil {
		t.Fatalf("write status: %v", err)
	}
	status := (Service{
		State:      NewRuntimeState(),
		StatusPath: statusPath,
		Now:        func() time.Time { return time.Date(2026, 6, 19, 1, 12, 0, 0, time.UTC) },
	}).Status()
	if status.Status != "restarting" || status.Message != "restarting" {
		t.Fatalf("fresh in-progress status should remain active: %#v", status)
	}
}

func TestValidateUpdaterAvailable(t *testing.T) {
	executable := fakeFileInfo{mode: 0755}
	service := Service{
		Geteuid:  func() int { return 0 },
		LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Stat: func(path string) (os.FileInfo, error) {
			if path == installerPath {
				return executable, nil
			}
			if path == "/run/systemd/system" {
				return fakeFileInfo{mode: os.ModeDir | 0755}, nil
			}
			return nil, os.ErrNotExist
		},
	}
	if err := service.ValidateUpdaterAvailable(); err != nil {
		t.Fatalf("ValidateUpdaterAvailable returned error: %v", err)
	}

	service.Geteuid = func() int { return 1000 }
	if err := service.ValidateUpdaterAvailable(); err == nil {
		t.Fatal("expected non-root validation error")
	}
}

func TestStartReturnsUpdaterUnavailable(t *testing.T) {
	service := Service{
		State:    NewRuntimeState(),
		LogPath:  filepath.Join(t.TempDir(), "update.log"),
		Geteuid:  func() int { return 0 },
		LookPath: func(string) (string, error) { return "", errors.New("missing") },
	}
	_, _, _, err := service.Start(context.Background(), "v1.0.0")
	serviceErr, ok := err.(Error)
	if !ok || serviceErr.Code != "updater_unavailable" {
		t.Fatalf("unexpected error: %#v", err)
	}
}

type fakeFileInfo struct {
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() interface{}   { return nil }
