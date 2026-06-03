<script setup>
import { ref, onMounted } from 'vue'
import { useSystemStats } from '../composables/useSystemStats.js'
import { useToast } from '../composables/useToast.js'
import { useApi } from '../composables/useApi.js'
import Skeleton from '../components/Skeleton.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import ConfirmModal from '../components/ConfirmModal.vue'
import api from '../api/index.js'

const toast = useToast()
const { stats, refresh } = useSystemStats()
const xrayRuntime = ref(null)
const { loading, error, exec, retry } = useApi()
const confirmModal = ref(null)

async function load() {
  await exec(async () => {
    const { data } = await api.get('/api/xray/runtime')
    xrayRuntime.value = data
    return data
  })
}

onMounted(load)

async function restartXray() {
  const ok = await confirmModal.value?.open('确认重启 Xray？短暂中断代理服务。')
  if (!ok) return
  try {
    await api.post('/api/xray/restart')
    toast.success('Xray 重启成功')
    await load()
    await refresh()
  } catch (e) { toast.error('重启失败: ' + (e.response?.data?.detail || e.message)) }
}
</script>

<template>
  <div>
    <div class="page-header">
      <h2>🛠️ 系统设置</h2>
    </div>

    <ErrorBanner :error="error" :retry="retry" />

    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon blue">🖥️</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.cpu?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">CPU</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">💾</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.ram?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">内存</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">💿</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.disk?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">磁盘</div>
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
      <h3>Xray 服务</h3>
      <div class="flex items-center gap-3 mb-4">
        <span
          class="badge"
          :class="stats.xray === 'running' ? 'badge-ok' : stats.xray === 'degraded' ? 'badge-warn' : 'badge-error'"
        >
          ● {{ stats.xray || '未知' }}
        </span>
        <button class="btn btn-sm" @click="restartXray">🔄 重启 Xray</button>
        <button class="btn btn-sm" @click="load(); refresh()">🔃 刷新</button>
      </div>

      <Skeleton v-if="loading" :lines="3" />
      <div v-else-if="xrayRuntime">
        <pre class="text-mono text-xs" style="background:var(--bg);padding:12px;border-radius:var(--radius-sm);overflow-x:auto;max-height:300px;white-space:pre-wrap;">{{ JSON.stringify(xrayRuntime, null, 2) }}</pre>
      </div>
    </div>

    <ConfirmModal ref="confirmModal" />
  </div>
</template>
