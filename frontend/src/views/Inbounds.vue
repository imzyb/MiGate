<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/index.js'

const inbounds = ref([])
const loading = ref(true)
const showCreate = ref(false)

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
    await load()
  } catch (e) { alert('创建失败: ' + (e.response?.data?.detail || e.message)) }
}

async function toggleInbound(id, enabled) {
  const action = enabled ? 'disable' : 'enable'
  try {
    await api.post(`/api/inbounds/${id}/${action}`)
    await load()
  } catch (e) { alert('操作失败: ' + (e.response?.data?.detail || e.message)) }
}

async function deleteInbound(id) {
  if (!confirm('确认删除此入站？')) return
  try {
    await api.post(`/api/inbounds/${id}/delete`)
    await load()
  } catch (e) { alert('删除失败: ' + (e.response?.data?.detail || e.message)) }
}

async function addClient(ibId, email) {
  try {
    await api.post(`/api/inbounds/${ibId}/clients/add`, { email })
    await load()
  } catch (e) { alert('添加失败: ' + (e.response?.data?.detail || e.message)) }
}

async function removeClient(ibId, clientId) {
  if (!confirm('确认删除此客户端？')) return
  try {
    await api.post(`/api/inbounds/${ibId}/clients/${clientId}/remove`)
    await load()
  } catch (e) { alert('删除失败: ' + (e.response?.data?.detail || e.message)) }
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

function clientStatus(cl) {
  // simplified — real status from traffic map
  return { icon: '●', color: 'var(--success)', badge: '正常', class: 'badge-ok' }
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

    <div v-if="showCreate" class="card">
      <h3>创建入站</h3>
      <form @submit.prevent="createInbound" class="form-grid">
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
        <button type="submit" class="btn btn-primary mt-4">创建</button>
      </form>
    </div>

    <div v-if="loading" class="card text-muted">加载中...</div>
    <div v-else-if="!inbounds.length" class="card empty-state">
      <div class="empty-icon">📡</div>
      <div class="empty-text">暂无入站规则</div>
    </div>

    <div v-for="ib in inbounds" :key="ib.id" class="card">
      <div class="flex justify-between items-center mb-4">
        <div>
          <span style="font-weight:700;font-size:15px;">{{ ib.remark }}</span>
          <span class="badge ml-2" :class="protoBadge[ib.protocol] || 'badge-muted'">{{ ib.protocol.toUpperCase() }}</span>
          <span class="text-muted text-sm ml-2">:{{ ib.port }}</span>
        </div>
        <div class="flex gap-2 items-center">
          <span class="badge" :class="ib.enabled ? 'badge-ok' : 'badge-off'">
            {{ ib.enabled ? '● 启用' : '○ 禁用' }}
          </span>
          <div class="toggle" :class="{ active: ib.enabled }" @click="toggleInbound(ib.id, ib.enabled)"></div>
          <button class="btn btn-sm btn-danger" @click="deleteInbound(ib.id)">删除</button>
        </div>
      </div>

      <div style="border-top:1px solid var(--border);padding-top:12px;">
        <div class="flex items-center gap-2 mb-2">
          <span>👤</span>
          <span style="font-weight:600;">客户端管理</span>
          <span class="badge badge-muted">{{ parseClients(ib.settings).length }} 个</span>
        </div>

        <div v-if="parseClients(ib.settings).length" class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>客户端</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="cl in parseClients(ib.settings)" :key="cl.id">
                <td>
                  <div style="font-weight:600;font-size:13px;">{{ cl.email || cl.id?.slice(0,8) }}</div>
                  <div class="text-muted text-xs">{{ cl.id?.slice(0,8) }}...</div>
                </td>
                <td>
                  <span class="badge badge-ok">正常</span>
                </td>
                <td>
                  <button class="btn btn-sm btn-danger" @click="removeClient(ib.id, cl.id)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="text-muted text-sm" style="padding:12px 0;">暂无客户端</div>

        <form @submit.prevent="addClient(ib.id, $event.target.email.value); $event.target.reset()" class="flex gap-2 mt-2">
          <input name="email" placeholder="输入客户端邮箱，回车添加" required style="flex:1;">
          <button type="submit" class="btn btn-primary btn-sm">➕ 添加</button>
        </form>
      </div>
    </div>
  </div>
</template>
