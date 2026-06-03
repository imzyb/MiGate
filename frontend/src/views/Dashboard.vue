<script setup>
import { ref, onMounted } from 'vue'
import { useSystemStats } from '../composables/useSystemStats.js'
import api from '../api/index.js'

const { stats } = useSystemStats()
const nodes = ref([])
const inbounds = ref([])

onMounted(async () => {
  try {
    const [nRes, iRes] = await Promise.all([
      api.get('/api/nodes'),
      api.get('/api/inbounds'),
    ])
    nodes.value = nRes.data
    inbounds.value = iRes.data
  } catch (e) {
    console.error('Dashboard load error', e)
  }
})

const enabledNodes = $computed(() => nodes.value.filter(n => n.enabled).length)
const enabledInbounds = $computed(() => inbounds.value.filter(i => i.enabled).length)

function statusColor(s) {
  if (s === 'running' || s === 'active') return 'var(--success)'
  if (s === 'degraded') return 'var(--warn)'
  return 'var(--danger)'
}

function fmtBytes(n) {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = Number(n)
  for (const u of units) {
    if (Math.abs(v) < 1024) return `${v.toFixed(1)} ${u}`
    v /= 1024
  }
  return `${v.toFixed(1)} PB`
}
</script>

<template>
  <div>
    <div class="page-header">
      <h2>📊 仪表盘</h2>
    </div>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon blue">🖥️</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.cpu?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">CPU 使用率</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">💾</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.ram?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">内存使用率</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">💿</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.disk?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">磁盘使用率</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon orange">⏱️</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.uptime || '—' }}</div>
          <div class="stat-label">运行时间</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Xray 状态</h3>
      <div class="flex items-center gap-3">
        <span
          class="badge"
          :class="stats.xray === 'running' ? 'badge-ok' : stats.xray === 'degraded' ? 'badge-warn' : 'badge-error'"
        >
          ● {{ stats.xray || '未知' }}
        </span>
      </div>
    </div>

    <div class="card">
      <h3>概览</h3>
      <div class="flex gap-4" style="flex-wrap:wrap;">
        <div>
          <span class="text-muted text-sm">节点</span>
          <div style="font-size:24px;font-weight:700;">{{ enabledNodes }} <span class="text-muted text-sm">/ {{ nodes.length }}</span></div>
        </div>
        <div>
          <span class="text-muted text-sm">入站</span>
          <div style="font-size:24px;font-weight:700;">{{ enabledInbounds }} <span class="text-muted text-sm">/ {{ inbounds.length }}</span></div>
        </div>
      </div>
    </div>
  </div>
</template>
