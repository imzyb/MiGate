<script setup>
import { ref, onMounted } from 'vue'
import { useSystemStats } from '../composables/useSystemStats.js'
import { useApi } from '../composables/useApi.js'
import Skeleton from '../components/Skeleton.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import api from '../api/index.js'

const { stats } = useSystemStats()
const { data: overview, loading, error, exec, retry } = useApi()
const nodes = ref([])
const inbounds = ref([])
const traffic = ref([])
const trafficLoading = ref(false)

async function load() {
  await exec(async () => {
    const [nRes, iRes] = await Promise.all([
      api.get('/api/nodes'),
      api.get('/api/inbounds'),
    ])
    nodes.value = nRes.data
    inbounds.value = iRes.data
    return { nodes: nRes.data, inbounds: iRes.data }
  })
}

async function loadTraffic() {
  trafficLoading.value = true
  try {
    const { data } = await api.get('/api/stats/traffic')
    traffic.value = data.inbounds || []
  } catch (e) { /* xray not running */ }
  trafficLoading.value = false
}

onMounted(() => {
  load()
  loadTraffic()
  // Auto-refresh traffic every 30s
  setInterval(loadTraffic, 30000)
})

const enabledNodes = $computed(() => nodes.value.filter(n => n.enabled).length)
const enabledInbounds = $computed(() => inbounds.value.filter(i => i.enabled).length)
const totalUp = $computed(() => traffic.value.reduce((s, t) => s + (t.up_bytes || 0), 0))
const totalDown = $computed(() => traffic.value.reduce((s, t) => s + (t.down_bytes || 0), 0))

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

    <ErrorBanner :error="error" :retry="retry" />

    <!-- System Stats -->
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon blue">🖥️</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.cpu_percent?.toFixed(1) || stats.cpu?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">CPU 使用率</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">💾</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.ram_percent?.toFixed(1) || stats.ram?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">内存使用率</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">💿</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.disk_percent?.toFixed(1) || stats.disk?.toFixed(1) || '—' }}%</div>
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

    <!-- Xray Status + Overview -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
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
        <Skeleton v-if="loading" :lines="2" />
        <div v-else class="flex gap-4" style="flex-wrap:wrap;">
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

    <!-- Quick Actions -->
    <div class="card">
      <h3>⚡ 快捷操作</h3>
      <div class="flex gap-3" style="flex-wrap:wrap;">
        <router-link to="/nodes" class="btn">🔗 节点管理</router-link>
        <router-link to="/inbounds" class="btn">📡 入站规则</router-link>
        <router-link to="/xray" class="btn">⚙️ Xray 配置</router-link>
        <router-link to="/system" class="btn">🛠️ 系统设置</router-link>
      </div>
    </div>

    <!-- Traffic Stats -->
    <div class="card">
      <div class="flex justify-between items-center mb-3">
        <h3>📈 流量统计</h3>
        <button class="btn btn-sm" @click="loadTraffic">🔃 刷新</button>
      </div>
      <Skeleton v-if="trafficLoading" :lines="3" />
      <div v-else-if="traffic.length">
        <!-- Total -->
        <div class="flex gap-4 mb-3" style="flex-wrap:wrap;">
          <div>
            <span class="text-muted text-sm">总上行</span>
            <div style="font-size:20px;font-weight:700;color:var(--accent2);">↑ {{ fmtBytes(totalUp) }}</div>
          </div>
          <div>
            <span class="text-muted text-sm">总下行</span>
            <div style="font-size:20px;font-weight:700;color:var(--accent);">↓ {{ fmtBytes(totalDown) }}</div>
          </div>
          <div>
            <span class="text-muted text-sm">总计</span>
            <div style="font-size:20px;font-weight:700;">{{ fmtBytes(totalUp + totalDown) }}</div>
          </div>
        </div>
        <!-- Per-inbound table -->
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>入站</th>
                <th>协议</th>
                <th>端口</th>
                <th>状态</th>
                <th>上行</th>
                <th>下行</th>
                <th>合计</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="ib in traffic" :key="ib.id">
                <td class="text-sm font-semibold">{{ ib.remark }}</td>
                <td><span class="badge badge-muted">{{ ib.protocol?.toUpperCase() }}</span></td>
                <td class="text-mono text-sm">{{ ib.port }}</td>
                <td><span class="badge" :class="ib.enabled ? 'badge-ok' : 'badge-off'">{{ ib.enabled ? '●' : '○' }}</span></td>
                <td class="text-sm text-mono">↑ {{ fmtBytes(ib.up_bytes) }}</td>
                <td class="text-sm text-mono">↓ {{ fmtBytes(ib.down_bytes) }}</td>
                <td class="text-sm text-mono font-semibold">{{ fmtBytes(ib.total_bytes) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div v-else class="text-muted text-sm">
        暂无流量数据（Xray 未运行或无入站流量）
      </div>
    </div>
  </div>
</template>
