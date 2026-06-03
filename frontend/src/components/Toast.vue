<script setup>
import { useToast } from '../composables/useToast.js'

const { toasts, remove } = useToast()

const icons = { success: '✅', error: '❌', warn: '⚠️', info: 'ℹ️' }
</script>

<template>
  <div class="toast-container">
    <TransitionGroup name="toast">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="toast"
        :class="'toast-' + t.type"
        @click="remove(t.id)"
      >
        <span class="toast-icon">{{ icons[t.type] || 'ℹ️' }}</span>
        <span class="toast-msg">{{ t.message }}</span>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-container {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-width: 380px;
}

.toast {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  border-radius: 10px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  cursor: pointer;
  font-size: 14px;
  animation: slideIn 0.25s ease;
}

.toast-success { border-left: 3px solid var(--success); }
.toast-error { border-left: 3px solid var(--danger); }
.toast-warn { border-left: 3px solid var(--warn); }
.toast-info { border-left: 3px solid var(--accent); }

.toast-icon { font-size: 16px; flex-shrink: 0; }
.toast-msg { flex: 1; }

.toast-enter-active { animation: slideIn 0.25s ease; }
.toast-leave-active { animation: slideOut 0.2s ease; }

@keyframes slideIn {
  from { opacity: 0; transform: translateX(40px); }
  to { opacity: 1; transform: translateX(0); }
}
@keyframes slideOut {
  from { opacity: 1; transform: translateX(0); }
  to { opacity: 0; transform: translateX(40px); }
}
</style>
