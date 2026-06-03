<script setup>
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import api from '../api/index.js'
import { setAuth } from '../router.js'

const router = useRouter()
const route = useRoute()
const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function login() {
  error.value = ''
  loading.value = true
  try {
    const form = new URLSearchParams()
    form.append('username', username.value)
    form.append('password', password.value)
    await api.post('/login', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    setAuth(true)
    const redirect = route.query.redirect || '/dashboard'
    router.push(redirect)
  } catch (e) {
    error.value = e.response?.data?.detail || '登录失败'
  }
  loading.value = false
}
</script>

<template>
  <div class="login-page">
    <div class="login-bg"></div>
    <div class="card login-card">
      <div style="font-size:42px;margin-bottom:8px;">🛡️</div>
      <h2 class="login-title">MiGate</h2>
      <p class="login-subtitle">代理节点管理面板</p>
      <form @submit.prevent="login">
        <div class="form-group mb-4">
          <input v-model="username" placeholder="用户名" required autocomplete="username">
        </div>
        <div class="form-group mb-4">
          <input v-model="password" type="password" placeholder="密码" required autocomplete="current-password">
        </div>
        <div v-if="error" class="login-error">{{ error }}</div>
        <button type="submit" class="btn btn-primary login-btn" :disabled="loading">
          {{ loading ? '登录中...' : '登 录' }}
        </button>
      </form>
    </div>
  </div>
</template>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--bg);
  padding: 16px;
  position: relative;
  overflow: hidden;
}

.login-bg {
  position: absolute;
  inset: 0;
  background: 
    radial-gradient(circle at 20% 80%, rgba(16, 185, 129, 0.08) 0%, transparent 50%),
    radial-gradient(circle at 80% 20%, rgba(99, 102, 241, 0.08) 0%, transparent 50%);
  animation: bgPulse 8s ease-in-out infinite alternate;
}

@keyframes bgPulse {
  from { opacity: 0.5; }
  to { opacity: 1; }
}

.login-card {
  width: 100%;
  max-width: 380px;
  text-align: center;
  position: relative;
  z-index: 1;
  backdrop-filter: blur(10px);
  border: 1px solid var(--border);
}

.login-title {
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin-bottom: 4px;
  font-size: 28px;
}

.login-subtitle {
  color: var(--text-muted, #888);
  font-size: 13px;
  margin-bottom: 24px;
}

.login-error {
  color: var(--danger);
  font-size: 13px;
  margin-bottom: 8px;
  animation: fadeIn 0.2s ease;
}

.login-btn {
  width: 100%;
  padding: 10px;
  font-size: 15px;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-4px); }
  to { opacity: 1; transform: translateY(0); }
}

@media (max-width: 480px) {
  .login-card {
    max-width: 100%;
  }
}
</style>
