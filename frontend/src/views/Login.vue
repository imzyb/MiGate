<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import api from '../api/index.js'

const router = useRouter()
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
    router.push('/dashboard')
  } catch (e) {
    error.value = e.response?.data?.detail || '登录失败'
  }
  loading.value = false
}
</script>

<template>
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;background:var(--bg);">
    <div class="card" style="width:100%;max-width:380px;text-align:center;">
      <div style="font-size:36px;margin-bottom:8px;">🛡️</div>
      <h2 style="background:linear-gradient(135deg,var(--accent2),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:24px;">MiGate</h2>
      <form @submit.prevent="login">
        <div class="form-group mb-4">
          <input v-model="username" placeholder="用户名" required autocomplete="username">
        </div>
        <div class="form-group mb-4">
          <input v-model="password" type="password" placeholder="密码" required autocomplete="current-password">
        </div>
        <div v-if="error" class="text-sm mb-2" style="color:var(--danger);">{{ error }}</div>
        <button type="submit" class="btn btn-primary" style="width:100%;" :disabled="loading">
          {{ loading ? '登录中...' : '登录' }}
        </button>
      </form>
    </div>
  </div>
</template>
