<script setup>
import { ref } from 'vue'

const visible = ref(false)
const links = ref([])
const copiedIdx = ref(-1)

function open(nodeLinks) {
  links.value = nodeLinks || []
  visible.value = false
  copiedIdx.value = -1
  visible.value = true
}

function close() {
  visible.value = false
}

async function copyLink(link, idx) {
  try {
    await navigator.clipboard.writeText(link)
    copiedIdx.value = idx
    setTimeout(() => { copiedIdx.value = -1 }, 2000)
  } catch (e) {
    // fallback
    const ta = document.createElement('textarea')
    ta.value = link
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    copiedIdx.value = idx
    setTimeout(() => { copiedIdx.value = -1 }, 2000)
  }
}

function qrUrl(link) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(link)}`
}

defineExpose({ open })
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="visible" class="modal-overlay" @click.self="close">
        <div class="modal-box share-modal">
          <div class="share-header">
            <h3>🔗 分享链接</h3>
            <button class="btn btn-sm" @click="close">✕</button>
          </div>

          <div v-if="!links.length" class="empty-state" style="padding:20px;">
            <div class="empty-text">暂无分享链接</div>
          </div>

          <div v-else class="share-list">
            <div v-for="(link, idx) in links" :key="idx" class="share-item">
              <div class="share-link-row">
                <code class="share-link text-mono text-xs">{{ link }}</code>
                <button class="btn btn-sm" :class="copiedIdx === idx ? 'btn-ok' : ''" @click="copyLink(link, idx)">
                  {{ copiedIdx === idx ? '✓ 已复制' : '📋 复制' }}
                </button>
              </div>
              <div class="share-qr">
                <img :src="qrUrl(link)" :alt="'QR ' + idx" loading="lazy">
              </div>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.share-modal {
  max-width: 600px;
  max-height: 80vh;
  overflow-y: auto;
}

.share-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.share-header h3 { margin-bottom: 0; }

.share-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.share-item {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px;
}

.share-link-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 10px;
}

.share-link {
  flex: 1;
  background: var(--bg-input);
  padding: 6px 10px;
  border-radius: 6px;
  word-break: break-all;
  overflow-wrap: anywhere;
  font-size: 11px;
  line-height: 1.5;
  color: var(--accent2);
}

.share-qr {
  text-align: center;
}

.share-qr img {
  border-radius: 8px;
  background: #fff;
  padding: 8px;
  max-width: 180px;
}

.btn-ok {
  background: rgba(34,197,94,.15);
  border-color: rgba(34,197,94,.3);
  color: var(--success);
}

.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9000;
}

.modal-box {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  width: 90%;
}

.modal-enter-active { animation: fadeIn 0.2s ease; }
.modal-leave-active { animation: fadeOut 0.15s ease; }

@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes fadeOut { from { opacity: 1; } to { opacity: 0; } }
</style>
