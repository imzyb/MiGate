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
const confirmModal = ref(null)

async function load() {
  await exec(async () => {
    const { data } = await api.get('/api/xray/config/preview')
    config.value = typeof data === 'string' ? data : JSON.stringify(data, null, 2)
    return data
  })
}

onMounted(load)

async function saveConfig() {
  const ok = await confirmModal.value?.open('确认保存 Xray 配置？这将覆盖当前配置。')
  if (!ok) return
  saving.value = true
  try {
    await api.post('/api/xray/config/save', { config: config.value })
    toast.success('配置已保存')
  } catch (e) {
    toast.error('保存失败: ' + (e.response?.data?.detail || e.message))
  }
  saving.value = false
}
</script>

<template>
  <div>
    <div class="page-header flex justify-between items-center">
      <h2>⚙️ Xray 配置</h2>
      <div class="flex gap-2">
        <button class="btn btn-sm" @click="load()">🔃 刷新</button>
        <button class="btn btn-sm btn-primary" @click="saveConfig()" :disabled="saving">
          {{ saving ? '保存中...' : '💾 保存配置' }}
        </button>
      </div>
    </div>

    <ErrorBanner :error="error" :retry="retry" />

    <div class="card">
      <h3>配置预览</h3>
      <Skeleton v-if="loading" :lines="8" />
      <pre v-else class="text-mono text-sm" style="background:var(--bg);padding:16px;border-radius:var(--radius-sm);overflow-x:auto;max-height:600px;white-space:pre-wrap;word-break:break-all;">{{ config }}</pre>
    </div>

    <ConfirmModal ref="confirmModal" />
  </div>
</template>
