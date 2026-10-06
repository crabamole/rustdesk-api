<!--
=========================================================
* © 2024 Ronan LE MEILLAT for SCTG Development
=========================================================
This website use:
- Vite, Vue3, FontAwesome 6, TailwindCss 3
- And many others
-->
<template>
    <section class="bg-white dark:bg-dark">
        <div class="container mx-auto px-4">
            <div class="mb-4 flex flex-wrap gap-2">
                <button v-for="tab in TABS" :key="tab.key" @click="activeTab = tab.key"
                    :class="[activeTab === tab.key ? 'bg-slate-600 text-white' : 'bg-black/10', 'rounded-md px-4 py-2 font-medium']">
                    {{ tab.label }}
                </button>
            </div>
            <div class="mb-4 flex flex-wrap items-center gap-3">
                <input v-model="deviceFilter" type="text" placeholder="Filter by device"
                    class="rounded-md border-gray-300" />
                <select v-if="activeTab === 'conn'" v-model="connType" class="rounded-md border-gray-300">
                    <option value="">Any type</option>
                    <option v-for="(label, code) in CONN_TYPES" :key="code" :value="code">{{ label }}</option>
                </select>
            </div>
            <div class="max-w-full overflow-x-auto">
                <table class="w-full table-auto" data-testid="audit-table">
                    <thead>
                        <tr class="bg-slate-400 text-white">
                            <th v-for="col in columns" :key="col" class="py-3 px-3 text-left">{{ col }}</th>
                        </tr>
                    </thead>
                    <tbody v-if="activeTab === 'conn'">
                        <tr v-for="row in connRows" :key="row.guid" data-testid="audit-row" class="border-b border-[#E8E8E8]">
                            <td class="py-2 px-3">{{ formatTime(row.created_at) }}</td>
                            <td class="py-2 px-3">{{ row.active ? 'Active' : formatTime(row.end_time) }}</td>
                            <td class="py-2 px-3">{{ row.remote_name || row.remote }}</td>
                            <td class="py-2 px-3">{{ row.peer_name }} {{ row.peer_id ? `(${row.peer_id})` : '' }}</td>
                            <td class="py-2 px-3" data-testid="audit-viewer-machine">{{ machineLabel(row.peer_hostname, row.peer_os) }}</td>
                            <td class="py-2 px-3">{{ row.user }}</td>
                            <td class="py-2 px-3">{{ row.ip }}</td>
                            <td class="py-2 px-3">{{ connTypeLabel(row.conn_type) }}</td>
                            <td class="py-2 px-3">{{ authLabel(row.primary_auth, row.two_factor) }}</td>
                            <td class="py-2 px-3">{{ row.note }}</td>
                        </tr>
                    </tbody>
                    <tbody v-else-if="activeTab === 'file'">
                        <tr v-for="row in fileRows" :key="row.guid" data-testid="audit-row" class="border-b border-[#E8E8E8]">
                            <td class="py-2 px-3">{{ formatTime(row.created_at) }}</td>
                            <td class="py-2 px-3">{{ row.remote }}</td>
                            <td class="py-2 px-3">{{ row.peer_id }}</td>
                            <td class="py-2 px-3">{{ row.user }}</td>
                            <td class="py-2 px-3">{{ fileDirectionLabel(row.type) }}</td>
                            <td class="py-2 px-3">{{ row.path }}</td>
                            <td class="py-2 px-3">{{ fileCountLabel(row) }}</td>
                            <td class="py-2 px-3">{{ row.ip }}</td>
                        </tr>
                    </tbody>
                    <tbody v-else>
                        <tr v-for="row in alarmRows" :key="row.guid" data-testid="audit-row" class="border-b border-[#E8E8E8]">
                            <td class="py-2 px-3">{{ formatTime(row.created_at) }}</td>
                            <td class="py-2 px-3">{{ row.device }}</td>
                            <td class="py-2 px-3">{{ row.user }}</td>
                            <td class="py-2 px-3">{{ alarmLabel(row.typ) }}</td>
                            <td class="py-2 px-3">{{ alarmDetails(row.info) }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="mt-4 flex flex-wrap items-center gap-3">
                <button @click="current--" :disabled="current <= 1" class="rounded-md bg-black/20 px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed">Previous</button>
                <span class="text-sm">page {{ current }} of {{ pageCount }}</span>
                <button @click="current++" :disabled="current >= pageCount" class="rounded-md bg-black/20 px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed">Next</button>
                <span class="text-sm" role="status">{{ message }}</span>
            </div>
        </div>
    </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { AuditApi, AuditAlarmLog, AuditConnLog, AuditFileLog } from '@/api';
import { useUserStore } from '@/stores/sctgDeskStore';
import { CONN_TYPES, alarmLabel, authLabel, connTypeLabel, fileDirectionLabel, formatTime, likePattern, machineLabel } from '@/utilities/audit';

const PAGE_SIZE = 20;
const TABS = [
    { key: 'conn', label: 'Connections' },
    { key: 'file', label: 'Files' },
    { key: 'alarm', label: 'Alarms' },
] as const;

const activeTab = ref<'conn' | 'file' | 'alarm'>('conn');
const deviceFilter = ref('');
const connType = ref<number | ''>('');
const current = ref(1);
const total = ref(0);
const connRows = ref([] as AuditConnLog[]);
const fileRows = ref([] as AuditFileLog[]);
const alarmRows = ref([] as AuditAlarmLog[]);
const message = ref('');

const pageCount = computed(() => Math.max(1, Math.ceil(total.value / PAGE_SIZE)));

const columns = computed(() => {
    if (activeTab.value === 'conn') return ['Start', 'End', 'Device', 'Viewer', 'Viewer machine', 'User', 'Address', 'Type', 'Authentication', 'Note'];
    if (activeTab.value === 'file') return ['Time', 'Device', 'Viewer', 'User', 'Direction', 'Path', 'Files', 'Address'];
    return ['Time', 'Device', 'User', 'Type', 'Details'];
});

function api(): AuditApi {
    return new AuditApi(useUserStore().api_configuration);
}

function fail(error: any): void {
    console.error(error);
    message.value = `Failed: ${error?.response?.data ?? error}`;
}

/** `files` is `[name, size][]` (audit-api-spec.md §5); show the count and first names. */
function fileCountLabel(row: AuditFileLog): string {
    const pairs: [string, number][] = Array.isArray(row.files) ? row.files : [];
    const names = pairs.map(([name]) => name);
    if (names.length === 0) return row.num ? String(row.num) : '';
    const shown = names.slice(0, 3).join(', ');
    const count = row.num ?? names.length;
    return count > names.length ? `${count}: ${shown}, …` : `${count}: ${shown}`;
}

function alarmDetails(info: any): string {
    const parts = [info?.ip, info?.id, info?.name].filter(Boolean);
    return parts.join(' / ');
}

// Guards against an older response (slow network, fast typing) overwriting a newer one.
let requestId = 0;
let filterTimer: ReturnType<typeof setTimeout> | undefined;

function load(): void {
    const id = ++requestId;
    message.value = '';
    const pattern = likePattern(deviceFilter.value);
    if (activeTab.value === 'conn') {
        api().auditsConn(current.value, PAGE_SIZE, undefined, pattern, connType.value === '' ? undefined : Number(connType.value))
            .then((r) => { if (id === requestId) { connRows.value = r.data.data; total.value = r.data.total; } })
            .catch((error) => { if (id === requestId) fail(error); });
    } else if (activeTab.value === 'file') {
        api().auditsFile(current.value, PAGE_SIZE, undefined, pattern)
            .then((r) => { if (id === requestId) { fileRows.value = r.data.data; total.value = r.data.total; } })
            .catch((error) => { if (id === requestId) fail(error); });
    } else {
        api().auditsAlarm(current.value, PAGE_SIZE, undefined, pattern)
            .then((r) => { if (id === requestId) { alarmRows.value = r.data.data; total.value = r.data.total; } })
            .catch((error) => { if (id === requestId) fail(error); });
    }
}

watch([activeTab, connType], () => { current.value = 1; load(); });
watch(deviceFilter, () => {
    current.value = 1;
    clearTimeout(filterTimer);
    filterTimer = setTimeout(load, 300);
});
watch(current, load);
onMounted(load);
</script>
