<!--
Previous / Page N of M / Next under a server-paged table.
-->
<template>
  <div v-if="total > pageSize" class="mt-3 flex items-center justify-end gap-3 text-sm">
    <button :disabled="current <= 1" class="px-3 py-1 border rounded disabled:opacity-40" @click="emit('go', current - 1)">Previous</button>
    <span>Page {{ current }} of {{ pages }}</span>
    <button :disabled="current >= pages" class="px-3 py-1 border rounded disabled:opacity-40" @click="emit('go', current + 1)">Next</button>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{ current: number, total: number, pageSize: number }>();
const emit = defineEmits<{ go: [page: number] }>();
const pages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)));
</script>
