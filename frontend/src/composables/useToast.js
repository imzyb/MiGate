import { ref } from 'vue'

const toasts = ref([])
let nextId = 0

export function useToast() {
  function add(message, type = 'info', duration = 3000) {
    const id = nextId++
    toasts.value.push({ id, message, type })
    if (duration > 0) {
      setTimeout(() => remove(id), duration)
    }
  }

  function remove(id) {
    toasts.value = toasts.value.filter(t => t.id !== id)
  }

  function success(msg) { add(msg, 'success') }
  function error(msg) { add(msg, 'error', 5000) }
  function warn(msg) { add(msg, 'warn', 4000) }
  function info(msg) { add(msg, 'info') }

  return { toasts, add, remove, success, error, warn, info }
}
