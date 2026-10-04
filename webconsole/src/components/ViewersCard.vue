<!--
Machines whose RustDesk client logged in but never registered: they can connect out, not be controlled.
-->
<template>
  <section id="viewers" class="bg-white dark:bg-dark mt-10">
    <div class="container mx-auto">
      <h2 class="text-2xl font-bold tracking-tight text-gray-900">Viewers</h2>
      <p class="mt-1 mb-4 text-sm text-gray-500">
        Machines that signed in to connect to devices but cannot be controlled themselves.
      </p>
      <div class="max-w-full overflow-x-auto">
        <table class="w-full table-auto">
          <thead>
            <tr class="text-center bg-slate-500">
              <th v-for="h in ['Hostname', 'Id', 'Os', 'User', 'Last seen']" :key="h"
                class="py-3 px-3 text-base font-medium text-white">{{ h }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="v in viewers" :key="v.id + v.last_login" class="text-center text-base">
              <td class="border-b border-[#E8E8E8] py-3 px-2">{{ v.hostname }}</td>
              <td class="border-b border-[#E8E8E8] py-3 px-2">{{ v.id }}</td>
              <td class="border-b border-[#E8E8E8] py-3 px-2">{{ v.os }}</td>
              <td class="border-b border-[#E8E8E8] py-3 px-2">{{ v.user }}</td>
              <td class="border-b border-[#E8E8E8] py-3 px-2">{{ formatTime(v.last_seen) }}</td>
            </tr>
            <tr v-if="viewers.length === 0">
              <td colspan="5" class="py-3 px-2 text-center text-gray-500">No viewers</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="total > PAGE_SIZE" class="mt-3 flex items-center justify-end gap-3 text-sm">
        <button :disabled="current <= 1" class="px-3 py-1 border rounded disabled:opacity-40" @click="load(current - 1)">Previous</button>
        <span>Page {{ current }} of {{ pages }}</span>
        <button :disabled="current >= pages" class="px-3 py-1 border rounded disabled:opacity-40" @click="load(current + 1)">Next</button>
      </div>
    </div>
  </section>
</template>
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { PeerApi, ViewerDevice } from '@/api';
import { useUserStore } from '@/stores/sctgDeskStore';
import { formatTime } from '@/utilities/audit';

const PAGE_SIZE = 20;
const userStore = useUserStore();
const viewers = ref([] as ViewerDevice[]);
const total = ref(0);
const current = ref(1);
const pages = computed(() => Math.max(1, Math.ceil(total.value / PAGE_SIZE)));

function load(page: number) {
  new PeerApi(userStore.api_configuration).viewers(page, PAGE_SIZE).then((response) => {
    viewers.value = response.data.data;
    total.value = response.data.total;
    current.value = page;
  }).catch((error) => {
    console.error(error);
  });
}

onMounted(() => load(1));
</script>
