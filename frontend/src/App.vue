<script setup>
import { useRoute } from 'vue-router'
import Sidebar from './components/Sidebar.vue'
import Toast from './components/Toast.vue'
import ConfirmModal from './components/ConfirmModal.vue'

const route = useRoute()
const hideSidebar = route.meta?.hideSidebar
</script>

<template>
  <div class="layout" v-if="!hideSidebar">
    <Sidebar />
    <main class="main">
      <router-view v-slot="{ Component }">
        <Transition name="page" mode="out-in">
          <component :is="Component" />
        </Transition>
      </router-view>
    </main>
  </div>
  <router-view v-else />
  <Toast />
  <ConfirmModal />
</template>
