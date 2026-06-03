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

// Tabs
const activeTab = ref('services')

// Systemd units
const units = ref(null)
const unitsLoading = ref(false)

// Systemd status
const systemdStatus = ref(null)
const statusLoading = ref(false)

// Telegram notifications
const telegramBot = ref('')
const telegramChat = ref('')
const telegramSaving = ref(false)

// Backups
const backups = ref([])
const backupsLoading = ref(false)
const backupCreating = ref(false)

async function load() {
  await exec(async () => {
    const { data } = await api.get('/api/xray/runtime')
    xrayRuntime.value = data
    return data
  })
}

async function loadSystemdStatus() {
  statusLoading.value = true
  try {
    const { data } = await api.get('/api/systemd/status')
    systemdStatus.value = data
  } catch (e) { /* ignore */ }
  statusLoading.value = false
}

async function loadUnits() {
  unitsLoading.value = true
  try {
    const { data } = await api.get('/api/systemd/units/preview')
    units.value = data
  } catch (e) { /* ignore */ }
  unitsLoading.value = false
}

async function restartXray() {
  const ok = await confirmModal.value?.open('确认重启 Xray？短暂中断代理服务。')
  if (!ok) return
  try {
    await api.post('/api/xray/restart', null, { params: { confirm: 'RESTART' } })
    toast.success('Xray 重启成功 ✅')
    await load()
    await refresh()
    await loadSystemdStatus()
  } catch (e) { toast.error('重启失败: ' + (e.response?.data?.detail || e.message)) }
}

async function saveUnits() {
  try {
    await api.post('/api/systemd/units/save')
    toast.success('Systemd 单元文件已保存 💾')
    await loadUnits()
  } catch (e) { toast.error('保存失败: ' + (e.response?.data?.detail || e.message)) }
}

// Telegram notifications
async function loadTelegram() {
  try {
    const { data } = await api.get('/api/system/resources')
    // Telegram config comes from panel.json, not from this endpoint
    // We'll just show the save form
  } catch (e) { /* ignore */ }
}

async function saveTelegram() {
  telegramSaving.value = true
  try {
    const form = new FormData()
    form.append('bot_token', telegramBot.value)
    form.append('chat_id', telegramChat.value)
    await api.post('/api/notifications/telegram/save', form)
    toast.success('Telegram 通知设置已保存 📱')
  } catch (e) { toast.error('保存失败: ' + (e.response?.data?.detail || e.message)) }
  telegramSaving.value = false
}

// Backups
async function loadBackups() {
  backupsLoading.value = true
  try {
    const { data } = await api.get('/api/backup/list')
    backups.value = data.backups || []
  } catch (e) { /* ignore */ }
  backupsLoading.value = false
}

async function createBackup() {
  backupCreating.value = true
  try {
    await api.post('/api/backup/create')
    toast.success('备份已创建 💾')
    await loadBackups()
  } catch (e) { toast.error('备份失败: ' + (e.response?.data?.detail || e.message)) }
  backupCreating.value = false
}

async function restoreBackup(name) {
  const ok = await confirmModal.value?.open(`确认恢复备份 "${name}"？当前配置将被覆盖。`)
  if (!ok) return
  try {
    await api.post(`/api/backup/restore/${name}`)
    toast.success('备份已恢复 ✅')
  } catch (e) { toast.error('恢复失败: ' + (e.response?.data?.detail || e.message)) }
}

async function deleteBackup(name) {
  const ok = await confirmModal.value?.open(`确认删除备份 "${name}"？`)
  if (!ok) return
  try {
    await api.post(`/api/backup/delete/${name}`)
    toast.success('备份已删除 🗑️')
    await loadBackups()
  } catch (e) { toast.error('删除失败: ' + (e.response?.data?.detail || e.message)) }
}

onMounted(() => {
  load()
  loadSystemdStatus()
})
</script>

<template>
  <div>
    <div class="page-header">
      <h2>🛠️ 系统设置</h2>
    </div>

    <ErrorBanner :error="error" :retry="retry" />

    <!-- System Stats -->
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon blue">🖥️</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.cpu_percent?.toFixed(1) || stats.cpu?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">CPU</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">💾</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.ram_percent?.toFixed(1) || stats.ram?.toFixed(1) || '—' }}%</div>
          <div class="stat-label">内存</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">💿</div>
        <div class="stat-body">
          <div class="stat-value">{{ stats.disk_percent?.toFixed(1) || stats.disk?.toFixed(1) || '—' }}%</div>
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

    <!-- Tabs -->
    <div class="tabs">
      <button class="tab" :class="{ active: activeTab === 'services' }" @click="activeTab = 'services'">🔧 服务</button>
      <button class="tab" :class="{ active: activeTab === 'units' }" @click="activeTab = 'units'; loadUnits()">📄 单元文件</button>
      <button class="tab" :class="{ active: activeTab === 'notifications' }" @click="activeTab = 'notifications'">📱 通知</button>
      <button class="tab" :class="{ active: activeTab === 'backups' }" @click="activeTab = 'backups'; loadBackups()">💾 备份</button>
    </div>

    <!-- Services Tab -->
    <div v-if="activeTab === 'services'">
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
          <button class="btn btn-sm" @click="load(); refresh(); loadSystemdStatus()">🔃 刷新</button>
        </div>

        <Skeleton v-if="loading" :lines="3" />
        <div v-else-if="xrayRuntime">
          <div class="flex items-center gap-2 mb-2">
            <span class="badge" :class="xrayRuntime.status === 'running' ? 'badge-ok' : 'badge-warn'">
              {{ xrayRuntime.status }}
            </span>
            <span v-if="xrayRuntime.version" class="text-muted text-sm">v{{ xrayRuntime.version }}</span>
          </div>
          <div v-if="xrayRuntime.message" class="text-sm text-muted">{{ xrayRuntime.message }}</div>
        </div>
      </div>

      <!-- Systemd Services -->
      <div class="card">
        <h3>Systemd 服务状态</h3>
        <Skeleton v-if="statusLoading" :lines="3" />
        <div v-else-if="systemdStatus?.services" class="table-wrap">
          <table>
            <thead>
              <tr><th>服务</th><th>状态</th><th>输出</th></tr>
            </thead>
            <tbody>
              <tr v-for="(result, name) in systemdStatus.services" :key="name">
                <td class="text-mono text-sm font-semibold">{{ name }}</td>
                <td>
                  <span class="badge" :class="result.status === 'success' ? 'badge-ok' : 'badge-error'">
                    {{ result.status }}
                  </span>
                </td>
                <td class="text-sm text-muted">{{ result.stdout || result.stderr || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Units Tab -->
    <div v-if="activeTab === 'units'">
      <div class="card">
        <div class="flex justify-between items-center mb-3">
          <h3>📄 Systemd 单元文件</h3>
          <div class="flex gap-2">
            <button class="btn btn-sm" @click="loadUnits">🔃 刷新</button>
            <button class="btn btn-sm btn-primary" @click="saveUnits">💾 保存到磁盘</button>
          </div>
        </div>
        <Skeleton v-if="unitsLoading" :lines="6" />
        <div v-else-if="units">
          <div v-for="(content, name) in units" :key="name" class="mb-4">
            <h4 class="text-mono text-sm mb-2">{{ name }}</h4>
            <pre class="text-mono text-xs" style="background:var(--bg);padding:12px;border-radius:var(--radius-sm);overflow-x:auto;max-height:300px;white-space:pre-wrap;">{{ content }}</pre>
          </div>
        </div>
        <div v-else class="text-muted">无法加载单元文件</div>
      </div>
    </div>

    <!-- Notifications Tab -->
    <div v-if="activeTab === 'notifications'">
      <div class="card">
        <h3>📱 Telegram 通知</h3>
        <p class="text-muted text-sm mb-3">配置 Telegram Bot 推送重要事件通知</p>
        <form @submit.prevent="saveTelegram" style="display:grid;gap:12px;max-width:400px;">
          <div class="form-group">
            <label>Bot Token</label>
            <input v-model="telegramBot" placeholder="123456:ABC-DEF..." type="password">
          </div>
          <div class="form-group">
            <label>Chat ID</label>
            <input v-model="telegramChat" placeholder="-1001234567890">
          </div>
          <button type="submit" class="btn btn-primary" :disabled="telegramSaving">
            {{ telegramSaving ? '保存中...' : '💾 保存' }}
          </button>
        </form>
      </div>
    </div>

    <!-- Backups Tab -->
    <div v-if="activeTab === 'backups'">
      <div class="card">
        <div class="flex justify-between items-center mb-3">
          <h3>💾 备份管理</h3>
          <button class="btn btn-sm btn-primary" @click="createBackup" :disabled="backupCreating">
            {{ backupCreating ? '创建中...' : '➕ 创建备份' }}
          </button>
        </div>
        <Skeleton v-if="backupsLoading" :lines="3" />
        <div v-else-if="backups.length" class="table-wrap">
          <table>
            <thead>
              <tr><th>备份名称</th><th>大小</th><th>操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="b in backups" :key="b.name">
                <td class="text-mono text-sm">{{ b.name }}</td>
                <td class="text-sm text-muted">{{ b.size || '—' }}</td>
                <td>
                  <div class="flex gap-2">
                    <button class="btn btn-sm" @click="restoreBackup(b.name)">♻️ 恢复</button>
                    <button class="btn btn-sm btn-danger" @click="deleteBackup(b.name)">🗑️ 删除</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="text-muted text-sm">暂无备份</div>
      </div>
    </div>

    <ConfirmModal ref="confirmModal" />
  </div>
</template>

<style scoped>
.tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0;
}
.tab {
  padding: 8px 16px;
  background: none;
  border: none;
  color: var(--text-muted, #888);
  cursor: pointer;
  font-size: 14px;
  border-bottom: 2px solid transparent;
  transition: all 0.2s;
}
.tab:hover { color: var(--text); }
.tab.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
}
</style>
