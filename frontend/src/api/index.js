import axios from 'axios'
import { setAuth } from '../router.js'

// Detect base path from current URL (/panel/spa/ → /panel)
function getBasePath() {
  const path = window.location.pathname
  const spaIdx = path.indexOf('/spa/')
  return spaIdx >= 0 ? path.substring(0, spaIdx) : ''
}

const api = axios.create({
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
  baseURL: getBasePath(),
})

// Auth interceptor
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (!err.response) {
      err.message = '网络连接失败，请检查网络'
      return Promise.reject(err)
    }

    if (err.response.status === 401) {
      setAuth(false)
      const isLoginPage = window.location.pathname.includes('/login')
      if (!isLoginPage) {
        const base = getBasePath()
        window.location.href = base + '/spa/#/login'
      }
      return Promise.reject(err)
    }

    if (err.response.status === 403) {
      err.response.data = err.response.data || {}
      err.response.data.detail = err.response.data.detail || '权限不足'
    }

    if (err.response.status >= 500) {
      err.response.data = err.response.data || {}
      err.response.data.detail = err.response.data.detail || '服务器内部错误，请稍后重试'
    }

    return Promise.reject(err)
  }
)

export default api
