<!--
A select whose options come from a server search, for lists too long to load whole.
-->
<template>
  <div>
    <input v-model="q" type="search" placeholder="Search"
      class="mb-1 block w-full rounded-md border border-gray-300 p-2 text-sm" />
    <select :id="id" :value="modelValue" class="w-full p-2 border border-gray-300 rounded-md"
      @change="emit('update:modelValue', ($event.target as HTMLSelectElement).value)">
      <option v-if="nullLabel !== undefined" value="">{{ nullLabel }}</option>
      <option v-for="o in shown" :key="o.value" :value="o.value">{{ o.label }}</option>
    </select>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import type { Option } from '@/utilities/api';

const props = defineProps<{
  id?: string,
  modelValue: string,
  // Shown for the current value while it is not among the search results.
  selectedLabel?: string,
  nullLabel?: string,
  search: (q: string) => Promise<Option[]>,
}>();
const emit = defineEmits<{ 'update:modelValue': [value: string] }>();
const q = ref("");
const options = ref([] as Option[]);
const shown = computed(() => {
  const keep = props.modelValue !== "" && !options.value.some((o) => o.value === props.modelValue);
  return keep ? [{ value: props.modelValue, label: props.selectedLabel || props.modelValue }, ...options.value] : options.value;
});

let timer: ReturnType<typeof setTimeout> | undefined;
function load() {
  const search = q.value;
  props.search(search).then((found) => {
    if (search === q.value) options.value = found;
  });
}
watch(q, () => {
  clearTimeout(timer);
  timer = setTimeout(load, 300);
});
onMounted(load);
</script>
