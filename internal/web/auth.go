package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WithAuth enables panel login authentication. Requests to most routes must
// carry a valid session cookie obtained via POST /api/login.
func WithAuth(username, password string) Option {
	return func(cfg *routerConfig) {
		cfg.authEnabled = true
		cfg.authUsername = username
		cfg.authPassword = password
		secret := make([]byte, 32)
		_, _ = rand.Read(secret)
		cfg.sessionSecret = secret
	}
}

// authMiddleware wraps an http.Handler and checks the session cookie for all
// non-public routes when auth is enabled.
func authMiddleware(next http.Handler, cfg *routerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.authEnabled {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		// Public paths that do not need auth
		if path == "/login" || path == "/api/health" || path == "/api/login" || path == "/api/session" || path == "/api/vpngate/servers" || path == "/api/vpngate/probe" || path == "/api/vpngate/auto-health/status" || path == "/api/singbox/status" || path == "/api/singbox/version" || path == "/api/singbox/config" || strings.HasPrefix(path, "/sub/") {
			next.ServeHTTP(w, r)
			return
		}
		// Check session cookie
		cookie, err := r.Cookie("migate_session")
		if err != nil || !validateSessionToken(cookie.Value, cfg.sessionSecret) {
			if path == "/" && r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(loginPageHTML)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func createSessionToken(username string, secret []byte) string {
	expiry := time.Now().Add(24 * time.Hour).Unix()
	payload := fmt.Sprintf("%s:%d", username, expiry)
	sig := signMessage(payload, secret)
	return hex.EncodeToString([]byte(payload)) + "." + sig
}

func validateSessionToken(token string, secret []byte) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload := string(payloadBytes)
	idx := strings.LastIndex(payload, ":")
	if idx < 0 {
		return false
	}
	expiry, err := strconv.ParseInt(payload[idx+1:], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	expectedSig := signMessage(payload, secret)
	return hmac.Equal([]byte(parts[1]), []byte(expectedSig))
}

func signMessage(msg string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// loginHandler serves the login page HTML and handles POST /api/login.
func loginHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(loginPageHTML)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
			return
		}
		if !constantTimeStringEqual(req.Username, cfg.authUsername) || !constantTimeStringEqual(req.Password, cfg.authPassword) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_credentials"})
			return
		}
		token := createSessionToken(req.Username, cfg.sessionSecret)
		cookiePath := cfg.basePath
		if cookiePath == "" {
			cookiePath = "/"
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "migate_session",
			Value:    token,
			Path:     cookiePath,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func constantTimeStringEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// logoutHandler handles POST /api/logout by clearing the session cookie.
func logoutHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		cookiePath := cfg.basePath
		if cookiePath == "" {
			cookiePath = "/"
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "migate_session",
			Value:    "",
			Path:     cookiePath,
			HttpOnly: true,
			MaxAge:   -1,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
	}
}

// loginPageHTML is a self-contained login form served at /login.
// Vercel-style design with Geist font, CSS variables, light/dark support, and mobile responsive.
var loginPageHTML = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MiGate - Login</title>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--fg:#171717;--surface:#ffffff;--surface-subtle:#fafafa;--muted:#666666;--line:rgba(0,0,0,.08);--line-strong:#ebebeb;--accent:#171717;--danger:#dc2626;--focus:hsla(212,100%,48%,1);--shadow-sm:0 0 0 1px rgba(0,0,0,.08);--shadow-md:0 0 0 1px rgba(0,0,0,.08),0 2px 2px rgba(0,0,0,.04),0 8px 8px -8px rgba(0,0,0,.04);--radius-sm:6px;--radius-lg:12px;--space-4:16px;--space-5:20px;--space-6:24px;--text-sm:13px;--text-md:14px;--control-height:40px}
:root[data-theme="dark"]{--bg:#0a0a0a;--fg:#ededed;--surface:#111111;--surface-subtle:#18181b;--muted:#a1a1aa;--line:rgba(255,255,255,.10);--line-strong:rgba(255,255,255,.14);--accent:#ededed;--danger:#ef4444;--focus:rgba(99,102,241,.36);--shadow-sm:0 0 0 1px rgba(255,255,255,.10);--shadow-md:0 0 0 1px rgba(255,255,255,.10),0 12px 28px rgba(0,0,0,0)}
body{font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:var(--space-4)}
.login-card{background:var(--surface);border:none;border-radius:var(--radius-lg);padding:var(--space-6);width:360px;max-width:100%;box-shadow:var(--shadow-md)}
.login-card h1{font-size:22px;font-weight:600;margin-bottom:4px;text-align:center;color:var(--fg)}
.login-card p{color:var(--muted);font-size:var(--text-sm);text-align:center;margin-bottom:var(--space-6);line-height:1.5}
.form-group{display:grid;gap:6px;margin-bottom:var(--space-4)}
.form-group label{font-size:var(--text-sm);font-weight:500;color:var(--fg)}
.form-group input{width:100%;min-height:var(--control-height);padding:0 12px;background:var(--bg);border:none;border-radius:var(--radius-sm);color:var(--fg);font-size:var(--text-md);font-family:inherit;outline:none;transition:box-shadow .15s;box-shadow:var(--shadow-sm)}
.form-group input:focus{box-shadow:var(--shadow-sm),0 0 0 2px var(--focus)}
button{width:100%;min-height:var(--control-height);padding:0 16px;background:var(--accent);color:var(--bg);border:none;border-radius:var(--radius-sm);font-size:var(--text-md);font-weight:500;font-family:inherit;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.85}
.error{color:var(--danger);font-size:var(--text-sm);text-align:center;margin-top:var(--space-4);display:none;line-height:1.5}
@media (max-width: 480px){.login-card{padding:var(--space-5)}}
</style>
<script>
(function(){try{var t=localStorage.getItem('migate-theme')||(window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');document.documentElement.dataset.theme=t}catch(e){}})()
</script>
</head>
<body>
<div class="login-card">
<h1>MiGate</h1>
<p>面板登录</p>
<form id="loginForm">
<div class="form-group"><label for="username">用户名</label><input type="text" id="username" name="username" placeholder="admin" autocomplete="username" required></div>
<div class="form-group"><label for="password">密码</label><input type="password" id="password" name="password" placeholder="........" autocomplete="current-password" required></div>
<button type="submit">登录</button>
<div class="error" id="errorMsg"></div>
</form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit',async function(e){e.preventDefault();const u=document.getElementById('username').value;const p=document.getElementById('password').value;const base=(()=>{let path=window.location.pathname||'/';if(path.endsWith('/login'))path=path.slice(0,-6);if(path.endsWith('/')&&path!=='/')path=path.slice(0,-1);return path==='/'?'':path})();try{const r=await fetch(base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});if(r.ok){window.location.href=(base||'')+'/'}else{let msg='登录失败';try{const d=await r.json();msg=d.error||msg}catch{}const err=document.getElementById('errorMsg');err.textContent=msg;err.style.display='block'}}catch{const err=document.getElementById('errorMsg');err.textContent='网络错误';err.style.display='block'}})
</script>
</body>
</html>`)
