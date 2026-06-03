<script setup>
import { useRoute } from 'vue-router'

const route = useRoute()

const navItems = [
  { path: '/dashboard', icon: '📊', label: '仪表盘' },
  { path: '/nodes', icon: '🔗', label: '节点管理' },
  { path: '/inbounds', icon: '📡', label: '入站规则' },
  { path: '/xray', icon: '⚙️', label: 'Xray 配置' },
  { path: '/system', icon: '🛠️', label: '系统设置' },
]
</script>

<template>
  <aside class="sidebar">
    <div class="sidebar-brand">
      <span class="sidebar-brand-icon">🛡️</span>
      <span class="sidebar-brand-text">MiGate</span>
    </div>
    <nav class="sidebar-nav">
      <router-link
        v-for="item in navItems"
        :key="item.path"
        :to="item.path"
        class="nav-item"
        :class="{ active: route.path === item.path }"
      >
        <span class="nav-icon">{{ item.icon }}</span>
        <span>{{ item.label }}</span>
      </router-link>
    </nav>
  </aside>
</template>
