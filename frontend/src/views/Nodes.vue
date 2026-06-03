<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/index.js'
import { useToast } from '../composables/useToast.js'
import { useApi } from '../composables/useApi.js'
import ShareModal from '../components/ShareModal.vue'
import ConfirmModal from '../components/ConfirmModal.vue'
import Skeleton from '../components/Skeleton.vue'
import ErrorBanner from '../components/ErrorBanner.vue'

const toast = useToast()
const nodes = ref([])
const { loading, error, exec, retry } = useApi()
const showCreate = ref(false)
const shareModal = ref(null)
const confirmModal = ref(null)

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
  await exec(async () => {
    const { data } = await api.get('/api/nodes')
    nodes.value = data
    return data
  })
}

onMounted(load)

async function createNode() {
  try {
    await api.post('/api/nodes', form.value)
    form.value = { name: '', protocol: 'vless', host: '', port: 443, credential: '', stream_settings: '{}' }
    showCreate.value = false
    toast.success('节点创建成功')
    await load()
  } catch (e) { toast.error('创建失败: ' + (e.response?.data?.detail || e.message)) }
}

async function toggleNode(id, enabled) {
  const action = enabled ? 'disable' : 'enable'
  try {
    await api.post(`/api/nodes/${id}/${action}`)
    toast.success(`节点已${enabled ? '禁用' : '启用'}`)
    await load()
  } catch (e) { toast.error('操作失败: ' + (e.response?.data?.detail || e.message)) }
}

async function deleteNode(id) {
  const ok = await confirmModal.value?.open('确认删除此节点？删除后不可恢复。')
  if (!ok) return
  try {
    await api.post(`/api/nodes/${id}/delete`)
    toast.success('节点已删除')
    await load()
  } catch (e) { toast.error('删除失败: ' + (e.response?.data?.detail || e.message)) }
}

async function showShareLinks(node) {
  try {
    const { data } = await api.get(`/api/nodes/export`)
    const nodeLinks = data.filter(e => e.node_id === node.id).map(e => e.link)
    if (nodeLinks.length) {
      shareModal.value?.open(nodeLinks)
    } else {
      toast.warn('该节点暂无分享链接')
    }
  } catch (e) { toast.error('获取链接失败') }
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

    <ErrorBanner :error="error" :retry="retry" />

    <Transition name="slide">
      <div v-if="showCreate" class="card">
        <h3>创建节点</h3>
        <form @submit.prevent="createNode" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;">
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
          <div style="display:flex;align-items:flex-end;">
            <button type="submit" class="btn btn-primary" style="width:100%;">创建</button>
          </div>
        </form>
      </div>
    </Transition>

    <div class="card">
      <h3>节点列表</h3>
      <Skeleton v-if="loading" :lines="4" />
      <div v-else-if="error && !nodes.length" class="empty-state">
        <div class="empty-icon">⚠️</div>
        <div class="empty-text">加载失败，请重试</div>
      </div>
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
                <div>↑ {{ fmtBytes(node.up_bytes) }}</div>
                <div>↓ {{ fmtBytes(node.down_bytes) }}</div>
              </td>
              <td>
                <div class="flex gap-2" style="flex-wrap:wrap;">
                  <div
                    class="toggle"
                    :class="{ active: node.enabled }"
                    @click="toggleNode(node.id, node.enabled)"
                    :title="node.enabled ? '点击禁用' : '点击启用'"
                  ></div>
                  <button class="btn btn-sm" @click="showShareLinks(node)" title="分享链接">🔗</button>
                  <button class="btn btn-sm btn-danger" @click="deleteNode(node.id)" title="删除">🗑️</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <ShareModal ref="shareModal" />
    <ConfirmModal ref="confirmModal" />
  </div>
</template>

<style scoped>
.slide-enter-active { animation: slideDown 0.25s ease; }
.slide-leave-active { animation: slideUp 0.2s ease; }
@keyframes slideDown { from { opacity: 0; max-height: 0; } to { opacity: 1; max-height: 500px; } }
@keyframes slideUp { from { opacity: 1; max-height: 500px; } to { opacity: 0; max-height: 0; } }
</style>
