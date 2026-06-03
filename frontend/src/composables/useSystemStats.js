import { ref, onMounted, onUnmounted } from 'vue'
import api from '../api/index.js'

export function useSystemStats(intervalMs = 10000) {
  const stats = ref({ cpu: 0, ram: 0, disk: 0, uptime: '', xray: 'unknown' })
  const loading = ref(true)
  let timer = null

  async function fetch() {
    try {
      const { data } = await api.get('/api/system/resources')
      stats.value = data
    } catch (e) {
      console.error('Failed to fetch system stats', e)
    } finally {
      loading.value = false
    }
  }

  onMounted(() => {
    fetch()
    timer = setInterval(fetch, intervalMs)
  })

  onUnmounted(() => clearInterval(timer))

  return { stats, loading, refresh: fetch }
}
