<script setup>
defineProps({
  error: { type: String, default: '' },
  retry: { type: Function, default: null },
})
</script>

<template>
  <div v-if="error" class="error-banner">
    <div class="error-content">
      <span class="error-icon">⚠️</span>
      <span class="error-text">{{ error }}</span>
    </div>
    <button v-if="retry" class="btn btn-sm" @click="retry">🔄 重试</button>
  </div>
</template>

<style scoped>
.error-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: var(--radius-sm);
  margin-bottom: 16px;
  animation: fadeIn 0.3s ease;
}

.error-content {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.error-icon { font-size: 16px; flex-shrink: 0; }

.error-text {
  color: var(--danger);
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-4px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>
