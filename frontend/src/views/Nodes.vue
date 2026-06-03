<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/index.js'

const nodes = ref([])
const loading = ref(true)
const showCreate = ref(false)

// Create form
const form = ref({
  name: '', protocol: 'vless', host: '', port: 443, credential: '',
  stream_settings: '{}',
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
    const { data } = await api.get('/api/nodes')
    nodes.value = data
  } catch (e) { console.error(e) }
  loading.value = false
}

onMounted(load)

async function createNode() {
  try {
    await api.post('/api/nodes', form.value)
    form.value = { name: '', protocol: 'vless', host: '', port: 443, credential: '', stream_settings: '{}' }
    showCreate.value = false
    await load()
  } catch (e) { alert('创建失败: ' + (e.response?.data?.detail || e.message)) }
}

async function toggleNode(id, enabled) {
  const action = enabled ? 'disable' : 'enable'
  try {
    await api.post(`/api/nodes/${id}/${action}`)
    await load()
  } catch (e) { alert('操作失败: ' + (e.response?.data?.detail || e.message)) }
}

async function deleteNode(id) {
  if (!confirm('确认删除此节点？')) return
  try {
    await api.post(`/api/nodes/${id}/delete`)
    await load()
  } catch (e) { alert('删除失败: ' + (e.response?.data?.detail || e.message)) }
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
    <div class="page-header flex justify-between items-center">
      <h2>🔗 节点管理</h2>
      <button class="btn btn-primary" @click="showCreate = !showCreate">
        {{ showCreate ? '✕ 取消' : '➕ 创建节点' }}
      </button>
    </div>

    <div v-if="showCreate" class="card">
      <h3>创建节点</h3>
      <form @submit.prevent="createNode" class="form-grid">
        <div class="form-group">
          <label>名称</label>
          <input v-model="form.name" placeholder="节点名称" required>
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
          <label>地址</label>
          <input v-model="form.host" placeholder="IP 或域名" required>
        </div>
        <div class="form-group">
          <label>端口</label>
          <input v-model.number="form.port" type="number" min="1" max="65535" required>
        </div>
        <div class="form-group">
          <label>凭证 (UUID/密码)</label>
          <input v-model="form.credential" placeholder="UUID 或密码">
        </div>
        <button type="submit" class="btn btn-primary mt-4">创建</button>
      </form>
    </div>

    <div class="card">
      <h3>节点列表</h3>
      <div v-if="loading" class="text-muted">加载中...</div>
      <div v-else-if="!nodes.length" class="empty-state">
        <div class="empty-icon">🔗</div>
        <div class="empty-text">暂无节点，点击上方创建</div>
      </div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>名称</th>
              <th>协议</th>
              <th>地址</th>
              <th>状态</th>
              <th>流量</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="node in nodes" :key="node.id">
              <td>
                <div style="font-weight:600;">{{ node.name }}</div>
                <div class="text-muted text-xs">#{{ node.id }}</div>
              </td>
              <td>
                <span class="badge" :class="protoBadge[node.protocol] || 'badge-muted'">
                  {{ node.protocol.toUpperCase() }}
                </span>
              </td>
              <td class="text-sm text-mono">{{ node.host }}:{{ node.port }}</td>
              <td>
                <span class="badge" :class="node.enabled ? 'badge-ok' : 'badge-off'">
                  {{ node.enabled ? '● 启用' : '○ 禁用' }}
                </span>
              </td>
              <td class="text-sm">
                ↑ {{ fmtBytes(node.up_bytes) }}<br>
                ↓ {{ fmtBytes(node.down_bytes) }}
              </td>
              <td>
                <div class="flex gap-2">
                  <div
                    class="toggle"
                    :class="{ active: node.enabled }"
                    @click="toggleNode(node.id, node.enabled)"
                  ></div>
                  <button class="btn btn-sm btn-danger" @click="deleteNode(node.id)">删除</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
