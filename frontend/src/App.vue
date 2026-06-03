<script setup>
import { useRoute } from 'vue-router'
import Sidebar from './components/Sidebar.vue'

const route = useRoute()
const hideSidebar = route.meta?.hideSidebar
</script>

<template>
  <div class="layout" v-if="!hideSidebar">
    <Sidebar />
    <main class="main">
      <router-view />
    </main>
  </div>
  <router-view v-else />
</template>
