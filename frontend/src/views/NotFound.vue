<script setup>
import { useRouter } from 'vue-router'
const router = useRouter()
</script>

<template>
  <div class="not-found">
    <div class="nf-card">
      <div style="font-size:64px;margin-bottom:16px;">🔍</div>
      <h1 style="font-size:48px;font-weight:800;background:linear-gradient(135deg,var(--accent2),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;">404</h1>
      <p style="color:var(--text-muted,#888);margin-bottom:24px;">页面不存在</p>
      <button class="btn btn-primary" @click="router.push('/dashboard')">← 返回仪表盘</button>
    </div>
  </div>
</template>

<style scoped>
.not-found {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--bg);
}
.nf-card {
  text-align: center;
  padding: 48px;
}
</style>
