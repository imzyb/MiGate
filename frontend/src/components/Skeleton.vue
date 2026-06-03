<script setup>
defineProps({
  lines: { type: Number, default: 3 },
  avatar: { type: Boolean, default: false },
  card: { type: Boolean, default: false },
})
</script>

<template>
  <div :class="['skeleton', { 'skeleton-card': card }]">
    <div v-if="avatar" class="skeleton-avatar" />
    <div class="skeleton-lines">
      <div
        v-for="i in lines"
        :key="i"
        class="skeleton-line"
        :style="{ width: i === lines ? '60%' : '100%' }"
      />
    </div>
  </div>
</template>

<style scoped>
.skeleton {
  display: flex;
  gap: 12px;
  padding: 16px;
}

.skeleton-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
}

.skeleton-avatar {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  background: var(--border);
  animation: shimmer 1.5s infinite;
  flex-shrink: 0;
}

.skeleton-lines {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.skeleton-line {
  height: 14px;
  border-radius: 6px;
  background: var(--border);
  animation: shimmer 1.5s infinite;
}

.skeleton-line:nth-child(odd) {
  animation-delay: 0.15s;
}

@keyframes shimmer {
  0% { opacity: 0.6; }
  50% { opacity: 1; }
  100% { opacity: 0.6; }
}
</style>
