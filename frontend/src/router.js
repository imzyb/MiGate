import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './views/Dashboard.vue'
import Nodes from './views/Nodes.vue'
import Inbounds from './views/Inbounds.vue'
import XrayConfig from './views/XrayConfig.vue'
import System from './views/System.vue'
import Login from './views/Login.vue'
import NotFound from './views/NotFound.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'Dashboard', component: Dashboard, meta: { icon: '📊', title: '仪表盘', requiresAuth: true } },
  { path: '/nodes', name: 'Nodes', component: Nodes, meta: { icon: '🔗', title: '节点管理', requiresAuth: true } },
  { path: '/inbounds', name: 'Inbounds', component: Inbounds, meta: { icon: '📡', title: '入站规则', requiresAuth: true } },
  { path: '/xray', name: 'XrayConfig', component: XrayConfig, meta: { icon: '⚙️', title: 'Xray 配置', requiresAuth: true } },
  { path: '/system', name: 'System', component: System, meta: { icon: '🛠️', title: '系统设置', requiresAuth: true } },
  { path: '/login', name: 'Login', component: Login, meta: { hideSidebar: true } },
  { path: '/:pathMatch(.*)*', name: 'NotFound', component: NotFound, meta: { hideSidebar: true } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// Auth guard: check if authenticated before entering protected routes
let isAuthenticated = null  // null = unknown, true/false = known

router.beforeEach(async (to, from, next) => {
  // Update page title
  const title = to.meta?.title
  if (title) document.title = `${title} - MiGate`

  if (!to.meta?.requiresAuth) {
    return next()
  }

  // If we know we're authenticated, proceed
  if (isAuthenticated === true) {
    return next()
  }

  // Check auth by hitting a lightweight API endpoint
  try {
    const base = getBasePath()
    const resp = await fetch(base + '/api/dashboard', { credentials: 'same-origin' })
    if (resp.ok) {
      isAuthenticated = true
      return next()
    }
    if (resp.status === 401) {
      isAuthenticated = false
      return next({ name: 'Login', query: { redirect: to.fullPath } })
    }
    // Other errors (500 etc) - let the page handle it
    isAuthenticated = true
    return next()
  } catch (e) {
    // Network error - let the page handle it
    isAuthenticated = true
    return next()
  }
})

// Reset auth on login/logout
export function setAuth(val) {
  isAuthenticated = val
}

function getBasePath() {
  // The SPA is served at /{panel_base_path}/spa/
  // Extract the base path from the current URL
  const path = window.location.pathname
  const spaIdx = path.indexOf('/spa/')
  if (spaIdx >= 0) {
    return path.substring(0, spaIdx)
  }
  return ''
}

export default router
