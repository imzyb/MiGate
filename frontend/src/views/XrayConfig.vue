<script setup>
import { ref, onMounted } from 'vue'
import { useToast } from '../composables/useToast.js'
import { useApi } from '../composables/useApi.js'
import Skeleton from '../components/Skeleton.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import ConfirmModal from '../components/ConfirmModal.vue'
import api from '../api/index.js'

const toast = useToast()
const config = ref('')
const { loading, error, exec, retry } = useApi()
const saving = ref(false)
const validating = ref(false)
const applying = ref(false)
const restarting = ref(false)
const confirmModal = ref(null)
const confirmAction = ref('')
const confirmMsg = ref('')

// Xray runtime status
const runtime = ref(null)
const runtimeLoading = ref(false)

// X25519 keys
const x25519Keys = ref(null)
const x25519Loading = ref(false)

// Install plan
const installPlan = ref(null)
const installLoading = ref(false)

// Validation result
const validationResult = ref(null)

// Active tab
const activeTab = ref('config')

async function load() {
  await exec(async () => {
    const { data } = await api.get('/api/xray/config/preview')
    config.value = typeof data === 'string' ? data : JSON.stringify(data, null, 2)
    return data
  })
}

async function loadRuntime() {
  runtimeLoading.value = true
  try {
    const { data } = await api.get('/api/xray/runtime')
    runtime.value = data
  } catch (e) { /* ignore */ }
  runtimeLoading.value = false
}

async function validateConfig() {
  validating.value = true
  validationResult.value = null
  try {
    const { data } = await api.get('/api/xray/config/validate')
    validationResult.value = data
    if (data.status === 'valid') {
      toast.success('配置验证通过 ✅')
    } else {
      toast.error('配置验证失败 ❌')
    }
  } catch (e) {
    toast.error('验证请求失败: ' + (e.response?.data?.detail || e.message))
  }
  validating.value = false
}

async function saveConfig() {
  confirmAction.value = 'save'
  confirmMsg.value = '确认保存 Xray 配置？这将覆盖当前配置文件。'
  const ok = await confirmModal.value?.open(confirmMsg.value)
  if (!ok) return
  saving.value = true
  try {
    await api.post('/api/xray/config/save')
    toast.success('配置已保存 💾')
    await load()
  } catch (e) {
    toast.error('保存失败: ' + (e.response?.data?.detail || e.message))
  }
  saving.value = false
}

async function applyConfig() {
  confirmAction.value = 'apply'
  confirmMsg.value = '⚠️ 确认应用配置？\n\n这将：\n1. 保存配置\n2. 验证配置\n3. 重启 Xray 服务\n\n代理服务会短暂中断。'
  const ok = await confirmModal.value?.open(confirmMsg.value)
  if (!ok) return
  applying.value = true
  try {
    const { data } = await api.post('/api/xray/apply', null, { params: { confirm: 'APPLY' } })
    if (data.status === 'applied') {
      toast.success('配置已应用并重启 Xray ✅')
    } else {
      toast.warn(`应用结果: ${data.status}`)
    }
    await loadRuntime()
  } catch (e) {
    toast.error('应用失败: ' + (e.response?.data?.detail || e.message))
  }
  applying.value = false
}

async function restartXray() {
  confirmAction.value = 'restart'
  confirmMsg.value = '确认重启 Xray？代理服务会短暂中断。'
  const ok = await confirmModal.value?.open(confirmMsg.value)
  if (!ok) return
  restarting.value = true
  try {
    const { data } = await api.post('/api/xray/restart', null, { params: { confirm: 'RESTART' } })
    if (data.status === 'restarted') {
      toast.success('Xray 已重启 ✅')
    } else {
      toast.warn(`重启结果: ${data.status}`)
    }
    await loadRuntime()
  } catch (e) {
    toast.error('重启失败: ' + (e.response?.data?.detail || e.message))
  }
  restarting.value = false
}

async function generateX25519() {
  x25519Loading.value = true
  try {
    const { data } = await api.post('/api/xray/x25519')
    x25519Keys.value = data
    toast.success('X25519 密钥对已生成 🔑')
  } catch (e) {
    toast.error('生成失败: ' + (e.response?.data?.detail || e.message))
  }
  x25519Loading.value = false
}

async function loadInstallPlan() {
  installLoading.value = true
  try {
    const { data } = await api.get('/api/xray/install/dry-run')
    installPlan.value = data
  } catch (e) { /* ignore */ }
  installLoading.value = false
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(
    () => toast.success('已复制 ✅'),
    () => toast.error('复制失败')
  )
}

onMounted(() => {
  load()
  loadRuntime()
})
</script>

<template>
  <div>
    <div class="page-header flex justify-between items-center">
      <h2>⚙️ Xray 配置</h2>
      <div class="flex gap-2">
        <button class="btn btn-sm" @click="load(); loadRuntime()" :disabled="loading">🔃 刷新</button>
      </div>
    </div>

    <ErrorBanner :error="error" :retry="retry" />

    <!-- Tabs -->
    <div class="tabs">
      <button class="tab" :class="{ active: activeTab === 'config' }" @click="activeTab = 'config'">📝 配置</button>
      <button class="tab" :class="{ active: activeTab === 'runtime' }" @click="activeTab = 'runtime'">📊 运行状态</button>
      <button class="tab" :class="{ active: activeTab === 'tools' }" @click="activeTab = 'tools'">🔧 工具</button>
    </div>

    <!-- Config Tab -->
    <div v-if="activeTab === 'config'">
      <!-- Validation Result -->
      <div v-if="validationResult" class="card" :class="validationResult.status === 'valid' ? 'border-ok' : 'border-error'">
        <h3>{{ validationResult.status === 'valid' ? '✅ 配置有效' : '❌ 配置无效' }}</h3>
        <pre class="text-mono text-xs" style="background:var(--bg);padding:12px;border-radius:var(--radius-sm);overflow-x:auto;max-height:200px;white-space:pre-wrap;">{{ validationResult.stdout || validationResult.stderr || '无输出' }}</pre>
      </div>

      <div class="card">
        <h3>配置预览</h3>
        <Skeleton v-if="loading" :lines="8" />
        <div v-else>
          <pre class="text-mono text-sm" style="background:var(--bg);padding:16px;border-radius:var(--radius-sm);overflow-x:auto;max-height:500px;white-space:pre-wrap;word-break:break-all;">{{ config }}</pre>
        </div>
      </div>

      <!-- Action Buttons -->
      <div class="card">
        <h3>操作</h3>
        <div class="flex gap-3" style="flex-wrap:wrap;">
          <button class="btn" @click="validateConfig" :disabled="validating">
            {{ validating ? '验证中...' : '🔍 验证配置' }}
          </button>
          <button class="btn btn-primary" @click="saveConfig" :disabled="saving">
            {{ saving ? '保存中...' : '💾 保存配置' }}
          </button>
          <button class="btn btn-primary" @click="applyConfig" :disabled="applying" title="保存+验证+重启">
            {{ applying ? '应用中...' : '🚀 应用配置' }}
          </button>
          <button class="btn" @click="restartXray" :disabled="restarting">
            {{ restarting ? '重启中...' : '🔄 重启 Xray' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Runtime Tab -->
    <div v-if="activeTab === 'runtime'">
      <div class="card">
        <h3>Xray 运行状态</h3>
        <Skeleton v-if="runtimeLoading" :lines="4" />
        <div v-else-if="runtime">
          <div class="flex items-center gap-3 mb-3">
            <span class="badge" :class="runtime.status === 'running' ? 'badge-ok' : runtime.status === 'installed' ? 'badge-warn' : 'badge-error'">
              ● {{ runtime.status || '未知' }}
            </span>
            <span v-if="runtime.version" class="text-muted text-sm">v{{ runtime.version }}</span>
            <span v-if="runtime.bin_path" class="text-muted text-xs text-mono">{{ runtime.bin_path }}</span>
          </div>
          <div v-if="runtime.message" class="text-sm text-muted">{{ runtime.message }}</div>
          <pre class="text-mono text-xs mt-3" style="background:var(--bg);padding:12px;border-radius:var(--radius-sm);overflow-x:auto;max-height:300px;white-space:pre-wrap;">{{ JSON.stringify(runtime, null, 2) }}</pre>
        </div>
        <div v-else class="text-muted">无法获取运行状态</div>
      </div>
    </div>

    <!-- Tools Tab -->
    <div v-if="activeTab === 'tools'">
      <!-- X25519 Key Generation -->
      <div class="card">
        <h3>🔑 X25519 密钥生成</h3>
        <p class="text-muted text-sm mb-3">生成 Reality 协议所需的公私钥对</p>
        <button class="btn" @click="generateX25519" :disabled="x25519Loading">
          {{ x25519Loading ? '生成中...' : '🔑 生成密钥对' }}
        </button>
        <div v-if="x25519Keys" class="mt-3">
          <div class="form-group">
            <label>私钥 (Private Key)</label>
            <div class="flex gap-2">
              <input :value="x25519Keys.private_key" readonly class="text-mono">
              <button class="btn btn-sm" @click="copyToClipboard(x25519Keys.private_key)">📋</button>
            </div>
          </div>
          <div class="form-group">
            <label>公钥 (Public Key)</label>
            <div class="flex gap-2">
              <input :value="x25519Keys.public_key" readonly class="text-mono">
              <button class="btn btn-sm" @click="copyToClipboard(x25519Keys.public_key)">📋</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Install Plan -->
      <div class="card">
        <h3>📦 Xray 安装预览</h3>
        <p class="text-muted text-sm mb-3">预览 Xray 安装/更新步骤（dry-run）</p>
        <button class="btn" @click="loadInstallPlan" :disabled="installLoading">
          {{ installLoading ? '加载中...' : '📋 查看安装计划' }}
        </button>
        <div v-if="installPlan" class="mt-3">
          <pre class="text-mono text-xs" style="background:var(--bg);padding:12px;border-radius:var(--radius-sm);overflow-x:auto;max-height:300px;white-space:pre-wrap;">{{ JSON.stringify(installPlan, null, 2) }}</pre>
        </div>
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
.border-ok { border-left: 3px solid var(--accent2, #10b981); }
.border-error { border-left: 3px solid var(--danger, #ef4444); }
</style>
