import { ref } from 'vue'
import api from '../api/index.js'

/**
 * Composable for API calls with loading, error, and retry support.
 *
 * Usage:
 *   const { data, loading, error, exec, retry } = useApi()
 *   exec(() => api.get('/api/nodes'))
 */
export function useApi() {
  const data = ref(null)
  const loading = ref(false)
  const error = ref('')
  let _lastFn = null

  async function exec(fn) {
    _lastFn = fn
    loading.value = true
    error.value = ''
    try {
      const res = await fn()
      data.value = res.data ?? res
      return data.value
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || '请求失败'
      error.value = msg
      throw e
    } finally {
      loading.value = false
    }
  }

  async function retry() {
    if (_lastFn) return exec(_lastFn)
  }

  return { data, loading, error, exec, retry }
}
