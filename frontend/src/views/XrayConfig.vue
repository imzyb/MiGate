<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/index.js'

const config = ref('')
const loading = ref(true)

async function load() {
  loading.value = true
  try {
    const { data } = await api.get('/api/xray/config/preview')
    config.value = typeof data === 'string' ? data : JSON.stringify(data, null, 2)
  } catch (e) {
    config.value = '// 加载失败: ' + (e.response?.data?.detail || e.message)
  }
  loading.value = false
}

onMounted(load)
</script>

<template>
  <div>
    <div class="page-header">
      <h2>⚙️ Xray 配置</h2>
    </div>

    <div class="card">
      <h3>配置预览</h3>
      <div v-if="loading" class="text-muted">加载中...</div>
      <pre v-else class="text-mono text-sm" style="background:var(--bg);padding:16px;border-radius:var(--radius-sm);overflow-x:auto;max-height:600px;white-space:pre-wrap;word-break:break-all;">{{ config }}</pre>
    </div>
  </div>
</template>
