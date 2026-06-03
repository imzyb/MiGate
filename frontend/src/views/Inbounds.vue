<script setup>
import { ref, onMounted, computed } from 'vue'
import api from '../api/index.js'
import { useToast } from '../composables/useToast.js'

const toast = useToast()
const inbounds = ref([])
const loading = ref(true)
const showCreate = ref(false)
const expandedClient = ref(null)

const form = ref({
  remark: '', protocol: 'vless', port: 443, listen: '0.0.0.0',
  settings: '{"clients":[]}', stream_settings: '{}',
})

const protoBadge = {
  vless: 'badge-vless',
  vmess: 'badge-vmess',
  trojan: 'badge-trojan',
  shadowsocks: 'badge-shadowsocks',
}

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/api/inbounds')
    inbounds.value = data
  } catch (e) { console.error(e) }
  loading.value = false
}

onMounted(load)

async function createInbound() {
  try {
    await api.post('/api/inbounds', form.value)
    form.value = { remark: '', protocol: 'vless', port: 443, listen: '0.0.0.0', settings: '{"clients":[]}', stream_settings: '{}' }
    showCreate.value = false
    toast.success('入站创建成功')
    await load()
  } catch (e) { toast.error('创建失败: ' + (e.response?.data?.detail || e.message)) }
}

async function toggleInbound(id, enabled) {
  const action = enabled ? 'disable' : 'enable'
  try {
    await api.post(`/api/inbounds/${id}/${action}`)
    toast.success(`入站已${enabled ? '禁用' : '启用'}`)
    await load()
  } catch (e) { toast.error('操作失败: ' + (e.response?.data?.detail || e.message)) }
}

async function deleteInbound(id) {
  if (!confirm('确认删除此入站？')) return
  try {
    await api.post(`/api/inbounds/${id}/delete`)
    toast.success('入站已删除')
    await load()
  } catch (e) { toast.error('删除失败: ' + (e.response?.data?.detail || e.message)) }
}

async function addClient(ibId, email) {
  try {
    await api.post(`/api/inbounds/${ibId}/clients/add`, { email })
    toast.success('客户端已添加')
    await load()
  } catch (e) { toast.error('添加失败: ' + (e.response?.data?.detail || e.message)) }
}

async function removeClient(ibId, clientId) {
  if (!confirm('确认删除此客户端？')) return
  try {
    await api.post(`/api/inbounds/${ibId}/clients/${clientId}/remove`)
    toast.success('客户端已删除')
    await load()
  } catch (e) { toast.error('删除失败: ' + (e.response?.data?.detail || e.message)) }
}

async function saveLimits(ibId, email, limitGb, expireAt) {
  try {
    await api.post(`/api/inbounds/${ibId}/clients/${email}/limits`, {
      traffic_limit_gb: limitGb ? parseFloat(limitGb) : 0,
      expire_at: expireAt || '',
    })
    toast.success('限额已保存')
    await load()
  } catch (e) { toast.error('保存失败: ' + (e.response?.data?.detail || e.message)) }
}

function parseClients(settingsStr) {
  try { return JSON.parse(settingsStr).clients || [] }
  catch { return [] }
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

function toggleClientExpand(ibId, email) {
  const key = `${ibId}:${email}`
  expandedClient.value = expandedClient.value === key ? null : key
}
</script>

<template>
  <div>
    <div class="page-header flex justify-between items-center">
      <h2>📡 入站规则</h2>
      <button class="btn btn-primary" @click="showCreate = !showCreate">
        {{ showCreate ? '✕ 取消' : '➕ 创建入站' }}
      </button>
    </div>

    <Transition name="slide">
      <div v-if="showCreate" class="card">
        <h3>创建入站</h3>
        <form @submit.prevent="createInbound" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;">
          <div class="form-group">
            <label>备注</label>
            <input v-model="form.remark" placeholder="入站备注" required>
          </div>
          <div class="form-group">
            <label>协议</label>
            <select v-model="form.protocol">
              <option value="vless">VLESS</option>
              <option value="vmess">VMess</option>
              <option value="trojan">Trojan</option>
              <option value="shadowsocks">Shadowsocks</option>
            </select>
          </div>
          <div class="form-group">
            <label>端口</label>
            <input v-model.number="form.port" type="number" min="1" max="65535" required>
          </div>
          <div style="display:flex;align-items:flex-end;">
            <button type="submit" class="btn btn-primary" style="width:100%;">创建</button>
          </div>
        </form>
      </div>
    </Transition>

    <div v-if="loading" class="card text-muted" style="text-align:center;padding:40px;">加载中...</div>
    <div v-else-if="!inbounds.length" class="card empty-state">
      <div class="empty-icon">📡</div>
      <div class="empty-text">暂无入站规则</div>
    </div>

    <div v-for="ib in inbounds" :key="ib.id" class="card" style="animation-delay:0.05s;">
      <!-- Inbound header -->
      <div class="flex justify-between items-center mb-4">
        <div class="flex items-center gap-3">
          <span style="font-weight:700;font-size:15px;">{{ ib.remark }}</span>
          <span class="badge" :class="protoBadge[ib.protocol] || 'badge-muted'">{{ ib.protocol.toUpperCase() }}</span>
          <span class="text-mono text-sm" style="color:var(--accent2);">:{{ ib.port }}</span>
        </div>
        <div class="flex gap-2 items-center">
          <span class="badge" :class="ib.enabled ? 'badge-ok' : 'badge-off'">
            {{ ib.enabled ? '● 启用' : '○ 禁用' }}
          </span>
          <div class="toggle" :class="{ active: ib.enabled }" @click="toggleInbound(ib.id, ib.enabled)"></div>
          <button class="btn btn-sm btn-danger" @click="deleteInbound(ib.id)">🗑️</button>
        </div>
      </div>

      <!-- Traffic summary -->
      <div class="flex gap-4 mb-4" style="font-size:13px;">
        <span class="text-muted">↑ 上传: <b style="color:var(--text);">{{ fmtBytes(ib.up_bytes) }}</b></span>
        <span class="text-muted">↓ 下载: <b style="color:var(--text);">{{ fmtBytes(ib.down_bytes) }}</b></span>
      </div>

      <!-- Clients section -->
      <div style="border-top:1px solid var(--border);padding-top:14px;">
        <div class="flex items-center gap-2 mb-3">
          <span style="font-size:16px;">👤</span>
          <span style="font-weight:600;">客户端管理</span>
          <span class="badge badge-muted" style="font-size:10px;">{{ parseClients(ib.settings).length }} 个</span>
        </div>

        <div v-if="parseClients(ib.settings).length" class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>客户端</th>
                <th>状态</th>
                <th style="width:200px;">限额</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="cl in parseClients(ib.settings)" :key="cl.id">
                <td>
                  <div style="font-weight:600;font-size:13px;">{{ cl.email || cl.id?.slice(0,8) }}</div>
                  <div class="text-muted text-xs text-mono">{{ cl.id?.slice(0,12) }}...</div>
                </td>
                <td>
                  <span class="badge badge-ok">● 正常</span>
                </td>
                <td>
                  <div class="flex gap-2 items-center">
                    <input
                      :placeholder="'GB'"
                      style="width:70px;font-size:12px;padding:4px 6px;"
                      @keydown.enter.prevent="saveLimits(ib.id, cl.email || cl.id, $event.target.value, '')"
                    >
                    <button class="btn btn-sm" @click="saveLimits(ib.id, cl.email || cl.id, $event.target.previousElementSibling.value, '')">💾</button>
                  </div>
                </td>
                <td>
                  <div class="flex gap-2">
                    <button class="btn btn-sm" @click="toggleClientExpand(ib.id, cl.email || cl.id)" title="展开详情">📋</button>
                    <button class="btn btn-sm btn-danger" @click="removeClient(ib.id, cl.id)" title="删除">🗑️</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="text-muted text-sm" style="padding:16px 0;text-align:center;">暂无客户端</div>

        <!-- Add client form -->
        <form @submit.prevent="addClient(ib.id, $event.target.email.value); $event.target.reset()" class="flex gap-2 mt-2">
          <input name="email" placeholder="输入客户端邮箱，回车添加" required style="flex:1;">
          <button type="submit" class="btn btn-primary btn-sm">➕ 添加客户端</button>
        </form>
      </div>
    </div>
  </div>
</template>

<style scoped>
.slide-enter-active { animation: slideDown 0.25s ease; }
.slide-leave-active { animation: slideUp 0.2s ease; }
@keyframes slideDown { from { opacity: 0; max-height: 0; } to { opacity: 1; max-height: 500px; } }
@keyframes slideUp { from { opacity: 1; max-height: 500px; } to { opacity: 0; max-height: 0; } }
</style>
