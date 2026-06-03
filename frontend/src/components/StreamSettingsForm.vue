<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '{}' },
})
const emit = defineEmits(['update:modelValue'])

const network = ref('tcp')
const security = ref('none')

// TCP
const tcpHeaderType = ref('none')
const tcpRequestPath = ref('')

// WebSocket
const wsPath = ref('/')
const wsHost = ref('')

// gRPC
const grpcServiceName = ref('')

// HTTP/2
const h2Host = ref('')
const h2Path = ref('/')

// XHTTP
const xhttpPath = ref('/')
const xhttpHost = ref('')
const xhttpMode = ref('auto')

// TLS
const tlsSni = ref('')
const tlsAlpn = ref('')
const tlsFingerprint = ref('')

// Reality
const realityPublicKey = ref('')
const realityPrivateKey = ref('')
const realityShortId = ref('')
const realityDest = ref('')
const realityServerNames = ref('')
const realitySpiderX = ref('')

// Flow
const flow = ref('')

function buildJson() {
  const result = { network: network.value, security: security.value }

  if (network.value === 'tcp') {
    const tcp = {}
    if (tcpHeaderType.value !== 'none') tcp.header = { type: tcpHeaderType.value }
    if (tcpRequestPath.value) tcp.path = tcpRequestPath.value
    if (Object.keys(tcp).length) result.tcpSettings = tcp
  } else if (network.value === 'ws') {
    const ws = { path: wsPath.value || '/' }
    if (wsHost.value) ws.host = wsHost.value
    result.wsSettings = ws
  } else if (network.value === 'grpc') {
    result.grpcSettings = { serviceName: grpcServiceName.value }
  } else if (network.value === 'h2') {
    const h2 = {}
    if (h2Host.value) h2.host = h2Host.value.split(',').map(s => s.trim())
    if (h2Path.value) h2.path = h2Path.value
    result.h2Settings = h2
  } else if (network.value === 'xhttp') {
    const xhttp = { path: xhttpPath.value || '/' }
    if (xhttpHost.value) xhttp.host = xhttpHost.value
    if (xhttpMode.value !== 'auto') xhttp.mode = xhttpMode.value
    result.xhttpSettings = xhttp
  }

  if (security.value === 'tls') {
    const tls = {}
    if (tlsSni.value) tls.serverName = tlsSni.value
    if (tlsAlpn.value) tls.alpn = tlsAlpn.value.split(',').map(s => s.trim())
    if (tlsFingerprint.value) tls.fingerprint = tlsFingerprint.value
    result.tlsSettings = tls
  } else if (security.value === 'reality') {
    const reality = { publicKey: realityPublicKey.value, shortId: realityShortId.value }
    if (realityPrivateKey.value) reality.privateKey = realityPrivateKey.value
    if (realityDest.value) reality.dest = realityDest.value
    if (realityServerNames.value) reality.serverNames = realityServerNames.value.split(',').map(s => s.trim())
    if (realitySpiderX.value) reality.spiderX = realitySpiderX.value
    if (tlsFingerprint.value) reality.fingerprint = tlsFingerprint.value
    result.realitySettings = reality
  }

  if (flow.value) result.flow = flow.value

  return result
}

function emitUpdate() {
  emit('update:modelValue', JSON.stringify(buildJson()))
}

watch([network, security, tcpHeaderType, tcpRequestPath, wsPath, wsHost, grpcServiceName,
  h2Host, h2Path, xhttpPath, xhttpHost, xhttpMode,
  tlsSni, tlsAlpn, tlsFingerprint,
  realityPublicKey, realityPrivateKey, realityShortId, realityDest, realityServerNames, realitySpiderX,
  flow], emitUpdate, { deep: true })

// Parse existing value on mount
try {
  const existing = JSON.parse(props.modelValue)
  if (existing.network) network.value = existing.network
  if (existing.security) security.value = existing.security
  if (existing.flow) flow.value = existing.flow
  if (existing.tcpSettings) {
    tcpHeaderType.value = existing.tcpSettings.header?.type || 'none'
    tcpRequestPath.value = existing.tcpSettings.path || ''
  }
  if (existing.wsSettings) {
    wsPath.value = existing.wsSettings.path || '/'
    wsHost.value = existing.wsSettings.host || ''
  }
  if (existing.grpcSettings) grpcServiceName.value = existing.grpcSettings.serviceName || ''
  if (existing.h2Settings) {
    h2Host.value = Array.isArray(existing.h2Settings.host) ? existing.h2Settings.host.join(',') : (existing.h2Settings.host || '')
    h2Path.value = existing.h2Settings.path || '/'
  }
  if (existing.xhttpSettings) {
    xhttpPath.value = existing.xhttpSettings.path || '/'
    xhttpHost.value = existing.xhttpSettings.host || ''
    xhttpMode.value = existing.xhttpSettings.mode || 'auto'
  }
  if (existing.tlsSettings) {
    tlsSni.value = existing.tlsSettings.serverName || ''
    tlsAlpn.value = Array.isArray(existing.tlsSettings.alpn) ? existing.tlsSettings.alpn.join(',') : (existing.tlsSettings.alpn || '')
    tlsFingerprint.value = existing.tlsSettings.fingerprint || ''
  }
  if (existing.realitySettings) {
    realityPublicKey.value = existing.realitySettings.publicKey || ''
    realityPrivateKey.value = existing.realitySettings.privateKey || ''
    realityShortId.value = existing.realitySettings.shortId || ''
    realityDest.value = existing.realitySettings.dest || ''
    realityServerNames.value = Array.isArray(existing.realitySettings.serverNames) ? existing.realitySettings.serverNames.join(',') : (existing.realitySettings.serverNames || '')
    realitySpiderX.value = existing.realitySettings.spiderX || ''
    tlsFingerprint.value = existing.realitySettings.fingerprint || ''
  }
} catch {}
</script>

<template>
  <div class="stream-form">
    <h4 style="margin-bottom:12px;color:var(--accent2);">Stream Settings</h4>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
      <div class="form-group">
        <label>传输协议</label>
        <select v-model="network">
          <option value="tcp">TCP</option>
          <option value="ws">WebSocket</option>
          <option value="grpc">gRPC</option>
          <option value="h2">HTTP/2</option>
          <option value="xhttp">XHTTP (SplitHTTP)</option>
        </select>
      </div>
      <div class="form-group">
        <label>安全</label>
        <select v-model="security">
          <option value="none">None</option>
          <option value="tls">TLS</option>
          <option value="reality">Reality</option>
        </select>
      </div>
    </div>

    <!-- TCP -->
    <div v-if="network === 'tcp'" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="form-group">
        <label>Header Type</label>
        <select v-model="tcpHeaderType">
          <option value="none">none</option>
          <option value="http">http</option>
        </select>
      </div>
      <div class="form-group">
        <label>Path</label>
        <input v-model="tcpRequestPath" placeholder="/">
      </div>
    </div>

    <!-- WebSocket -->
    <div v-if="network === 'ws'" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="form-group">
        <label>Path</label>
        <input v-model="wsPath" placeholder="/">
      </div>
      <div class="form-group">
        <label>Host</label>
        <input v-model="wsHost" placeholder="cdn.example.com">
      </div>
    </div>

    <!-- gRPC -->
    <div v-if="network === 'grpc'" class="form-group">
      <label>Service Name</label>
      <input v-model="grpcServiceName" placeholder="grpc-service">
    </div>

    <!-- HTTP/2 -->
    <div v-if="network === 'h2'" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="form-group">
        <label>Host (逗号分隔)</label>
        <input v-model="h2Host" placeholder="host1.com,host2.com">
      </div>
      <div class="form-group">
        <label>Path</label>
        <input v-model="h2Path" placeholder="/">
      </div>
    </div>

    <!-- XHTTP -->
    <div v-if="network === 'xhttp'" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
      <div class="form-group">
        <label>Path</label>
        <input v-model="xhttpPath" placeholder="/">
      </div>
      <div class="form-group">
        <label>Host</label>
        <input v-model="xhttpHost" placeholder="cdn.example.com">
      </div>
      <div class="form-group">
        <label>Mode</label>
        <select v-model="xhttpMode">
          <option value="auto">auto</option>
          <option value="stream">stream</option>
          <option value="one">one</option>
        </select>
      </div>
    </div>

    <!-- TLS -->
    <div v-if="security === 'tls'" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
      <div class="form-group">
        <label>SNI</label>
        <input v-model="tlsSni" placeholder="example.com">
      </div>
      <div class="form-group">
        <label>ALPN (逗号分隔)</label>
        <input v-model="tlsAlpn" placeholder="h2,http/1.1">
      </div>
      <div class="form-group">
        <label>Fingerprint</label>
        <select v-model="tlsFingerprint">
          <option value="">无</option>
          <option value="chrome">chrome</option>
          <option value="firefox">firefox</option>
          <option value="safari">safari</option>
          <option value="edge">edge</option>
          <option value="ios">ios</option>
          <option value="android">android</option>
          <option value="random">random</option>
          <option value="randomized">randomized</option>
        </select>
      </div>
    </div>

    <!-- Reality -->
    <div v-if="security === 'reality'" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="form-group">
        <label>Public Key</label>
        <input v-model="realityPublicKey" placeholder="公钥">
      </div>
      <div class="form-group">
        <label>Private Key</label>
        <input v-model="realityPrivateKey" placeholder="私钥 (可选)">
      </div>
      <div class="form-group">
        <label>Short ID</label>
        <input v-model="realityShortId" placeholder="短 ID">
      </div>
      <div class="form-group">
        <label>Dest (目标)</label>
        <input v-model="realityDest" placeholder="example.com:443">
      </div>
      <div class="form-group">
        <label>Server Names (逗号分隔)</label>
        <input v-model="realityServerNames" placeholder="example.com,www.example.com">
      </div>
      <div class="form-group">
        <label>Fingerprint</label>
        <select v-model="tlsFingerprint">
          <option value="">无</option>
          <option value="chrome">chrome</option>
          <option value="firefox">firefox</option>
          <option value="safari">safari</option>
          <option value="random">random</option>
        </select>
      </div>
      <div class="form-group" style="grid-column:span 2;">
        <label>SpiderX (爬虫路径)</label>
        <input v-model="realitySpiderX" placeholder="/">
      </div>
    </div>

    <!-- Flow -->
    <div v-if="security !== 'none'" class="form-group" style="margin-top:12px;">
      <label>Flow</label>
      <select v-model="flow">
        <option value="">无</option>
        <option value="xtls-rprx-vision">xtls-rprx-vision</option>
      </select>
    </div>
  </div>
</template>

<style scoped>
.stream-form {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 16px;
  margin-top: 12px;
}

h4 {
  font-size: 14px;
  font-weight: 600;
}
</style>
