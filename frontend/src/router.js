import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './views/Dashboard.vue'
import Nodes from './views/Nodes.vue'
import Inbounds from './views/Inbounds.vue'
import XrayConfig from './views/XrayConfig.vue'
import System from './views/System.vue'
import Login from './views/Login.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'Dashboard', component: Dashboard, meta: { icon: '📊', title: '仪表盘' } },
  { path: '/nodes', name: 'Nodes', component: Nodes, meta: { icon: '🔗', title: '节点管理' } },
  { path: '/inbounds', name: 'Inbounds', component: Inbounds, meta: { icon: '📡', title: '入站规则' } },
  { path: '/xray', name: 'XrayConfig', component: XrayConfig, meta: { icon: '⚙️', title: 'Xray 配置' } },
  { path: '/system', name: 'System', component: System, meta: { icon: '🛠️', title: '系统设置' } },
  { path: '/login', name: 'Login', component: Login, meta: { hideSidebar: true } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
