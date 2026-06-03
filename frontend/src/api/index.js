import axios from 'axios'

const api = axios.create({
  headers: { 'Content-Type': 'application/json' },
})

// Auth interceptor
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api
