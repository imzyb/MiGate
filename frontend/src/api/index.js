import axios from 'axios'

const api = axios.create({
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
})

// Auth interceptor
api.interceptors.response.use(
  (res) => res,
  (err) => {
    // Network error
    if (!err.response) {
      err.message = '网络连接失败，请检查网络'
      return Promise.reject(err)
    }

    // 401 → redirect to login
    if (err.response.status === 401) {
      const isLoginPage = window.location.pathname.includes('/login')
      if (!isLoginPage) {
        window.location.href = '/login'
      }
      return Promise.reject(err)
    }

    // 403 → permission denied
    if (err.response.status === 403) {
      err.response.data = err.response.data || {}
      err.response.data.detail = err.response.data.detail || '权限不足'
    }

    // 500+ → server error
    if (err.response.status >= 500) {
      err.response.data = err.response.data || {}
      err.response.data.detail = err.response.data.detail || '服务器内部错误，请稍后重试'
    }

    return Promise.reject(err)
  }
)

export default api
