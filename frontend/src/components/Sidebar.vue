<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { setAuth } from '../router.js'
import api from '../api/index.js'

const route = useRoute()
const router = useRouter()
const mobileOpen = ref(false)
const version = ref('')
const xrayStatus = ref('unknown')

const navItems = [
  { path: '/dashboard', icon: '📊', label: '仪表盘' },
  { path: '/nodes', icon: '🔗', label: '节点管理' },
  { path: '/inbounds', icon: '📡', label: '入站规则' },
  { path: '/xray', icon: '⚙️', label: 'Xray 配置' },
  { path: '/system', icon: '🛠️', label: '系统设置' },
]

function closeMobile() {
  mobileOpen.value = false
}

async function logout() {
  try { await api.post('/logout') } catch (e) { /* ignore */ }
  setAuth(false)
  router.push('/login')
}

onMounted(async () => {
  try {
    const { data } = await api.get('/api/dashboard')
    if (data.cards?.version) version.value = data.cards.version
    if (data.status?.xray) xrayStatus.value = data.status.xray
  } catch (e) { /* ignore */ }
})
</script>

<template>
  <!-- Mobile hamburger button -->
  <button class="mobile-menu-btn" @click="mobileOpen = !mobileOpen" :aria-label="mobileOpen ? '关闭菜单' : '打开菜单'">
    <span :class="['hamburger', { open: mobileOpen }]">
      <span></span><span></span><span></span>
    </span>
  </button>

  <!-- Backdrop -->
  <div v-if="mobileOpen" class="sidebar-backdrop" @click="closeMobile" />

  <aside class="sidebar" :class="{ 'mobile-open': mobileOpen }">
    <div class="sidebar-brand">
      <span class="sidebar-brand-icon">🛡️</span>
      <span class="sidebar-brand-text">MiGate</span>
      <span v-if="version" class="sidebar-version">{{ version }}</span>
    </div>
    <nav class="sidebar-nav">
      <router-link
        v-for="item in navItems"
        :key="item.path"
        :to="item.path"
        class="nav-item"
        :class="{ active: route.path === item.path }"
        @click="closeMobile"
      >
        <span class="nav-icon">{{ item.icon }}</span>
        <span>{{ item.label }}</span>
      </router-link>
    </nav>

    <!-- Bottom section -->
    <div class="sidebar-bottom">
      <div class="sidebar-status">
        <span class="status-dot" :class="xrayStatus === 'running' ? 'dot-ok' : xrayStatus === 'degraded' ? 'dot-warn' : 'dot-error'"></span>
        <span class="text-xs">Xray {{ xrayStatus }}</span>
      </div>
      <button class="nav-item logout-btn" @click="logout">
        <span class="nav-icon">🚪</span>
        <span>退出登录</span>
      </button>
    </div>
  </aside>
</template>

<style scoped>
.mobile-menu-btn {
  display: none;
  position: fixed;
  top: 14px;
  left: 14px;
  z-index: 200;
  width: 40px;
  height: 40px;
  border-radius: var(--radius-sm);
  background: var(--bg-card);
  border: 1px solid var(--border);
  cursor: pointer;
  align-items: center;
  justify-content: center;
  padding: 0;
}

.hamburger {
  display: flex;
  flex-direction: column;
  gap: 4px;
  width: 18px;
}

.hamburger span {
  display: block;
  height: 2px;
  background: var(--text);
  border-radius: 1px;
  transition: all 0.3s ease;
}

.hamburger.open span:nth-child(1) { transform: rotate(45deg) translateY(6px); }
.hamburger.open span:nth-child(2) { opacity: 0; }
.hamburger.open span:nth-child(3) { transform: rotate(-45deg) translateY(-6px); }

.sidebar-backdrop {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.5);
  z-index: 99;
}

.sidebar-bottom {
  margin-top: auto;
  padding-top: 12px;
  border-top: 1px solid var(--border);
}

.sidebar-status {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 14px;
  color: var(--text-muted, #888);
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
}

.dot-ok { background: var(--accent2, #10b981); }
.dot-warn { background: #f59e0b; }
.dot-error { background: var(--danger, #ef4444); }

.sidebar-version {
  font-size: 10px;
  color: var(--text-muted, #666);
  margin-left: auto;
  font-weight: 400;
}

.logout-btn {
  color: var(--text-muted, #888) !important;
  font-size: 13px !important;
  opacity: 0.7;
  transition: opacity 0.2s;
}

.logout-btn:hover {
  opacity: 1;
  color: var(--danger, #ef4444) !important;
}

@media (max-width: 768px) {
  .mobile-menu-btn { display: flex; }
  .sidebar-backdrop { display: block; }

  .sidebar {
    transform: translateX(-100%);
    transition: transform 0.3s ease;
  }

  .sidebar.mobile-open {
    transform: translateX(0);
  }
}
</style>
