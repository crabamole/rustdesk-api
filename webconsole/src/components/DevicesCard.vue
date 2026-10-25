<!--
=========================================================
* © 2024 Ronan LE MEILLAT for SCTG Development
=========================================================
This website use:
- Vite, Vue3, FontAwesome 6, TailwindCss 3
- And many others
-->
<template>
        <!-- ====== Table Section Start -->
        <section class="bg-white dark:bg-dark">
          <div class="container mx-auto">
            <div class="flex flex-wrap -mx-4">
              <div class="w-full px-4">
                <input v-model="list.q.value" type="search" placeholder="Search ID or hostname"
                  class="mb-3 block w-full max-w-sm rounded-md border border-gray-300 p-2 text-sm" />
                <select v-model="filter" data-testid="device-admission-filter"
                  class="mb-3 block w-full max-w-sm rounded-md border border-gray-300 p-2 text-sm">
                  <option :value="undefined">All devices</option>
                  <option :value="0">Pending</option>
                  <option :value="2">Rejected</option>
                </select>
                <div class="max-w-full overflow-x-auto">
                  <table class="w-full table-auto">
                    <thead class="bg-slate-400">
                      <tr class="text-center bg-primary">
                        <th
                          class="w-1/6 min-w-[160px] border-l border-transparent py-4 px-3 text-lg font-medium text-white lg:py-7 lg:px-4">
                          Id
                        </th>
                        <th class="w-1/6 min-w-[160px] py-4 px-3 text-lg font-medium text-white lg:py-7 lg:px-4">
                          Status
                        </th>
                        <th class="w-1/6 min-w-[160px] py-4 px-3 text-lg font-medium text-white lg:py-7 lg:px-4">
                          Admission
                        </th>
                        <th class="w-1/6 min-w-[160px] py-4 px-3 text-lg font-medium text-white lg:py-7 lg:px-4">
                          Username
                        </th>
                        <th class="w-1/6 min-w-[160px] py-4 px-3 text-lg font-medium text-white lg:py-7 lg:px-4">
                          Os
                        </th>
                        <th class="w-1/6 min-w-[160px] py-4 px-3 text-lg font-medium text-white lg:py-7 lg:px-4">
                          Ip
                        </th>
                        <th
                          class="w-1/6 min-w-[160px] border-r border-transparent py-4 px-3 text-lg font-medium text-white lg:py-7 lg:px-4">
                          Cpu
                        </th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="peer in list.items.value" :key="peer.guid">
                        <td
                          class="text-dark border-b border-l border-[#E8E8E8] bg-[#F3F6FF] dark:bg-dark-3 dark:border-dark dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          <ClipboardButton>{{ peer.id }}</ClipboardButton>
                        </td>
                        <td
                          class="text-dark border-b border-[#E8E8E8] bg-white dark:border-dark dark:bg-dark-2 dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          {{ peer.status }}<br/>{{ peer.last_online }}
                        </td>
                        <td data-testid="device-admission"
                          class="text-dark border-b border-[#E8E8E8] bg-[#F3F6FF] dark:bg-dark-3 dark:border-dark dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          {{ peer.admission }}
                        </td>
                        <td
                          class="text-dark border-b border-[#E8E8E8] bg-[#F3F6FF] dark:bg-dark-3 dark:border-dark dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          {{ peer.info.username }}
                        </td>
                        <td
                          class="text-dark border-b border-[#E8E8E8] bg-white dark:border-dark dark:bg-dark-2 dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          {{ peer.info.os }}
                        </td>
                        <td
                          class="text-dark border-b border-[#E8E8E8] bg-[#F3F6FF] dark:bg-dark-3 dark:border-dark dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          {{ peer.info.ip }}
                        </td>
                        <td
                          class="text-dark border-b border-[#E8E8E8] bg-white dark:bg-dark-3 dark:border-dark dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          {{ peer.info.cpu }}
                        </td>
                        <td
                          class="text-dark border-b border-r border-[#E8E8E8] bg-[#F3F6FF] dark:border-dark dark:bg-dark-2 dark:text-dark-7 py-5 px-2 text-center text-base font-medium">
                          <button v-for="a in admissions.filter((x) => x.state !== peer.admission)" :key="a.state" @click="admit(peer.id, a.state)" :data-testid="a.testid"
                            class="mr-2 inline-block px-6 py-2.5 border rounded-md border-primary text-primary hover:bg-primary hover:text-white font-medium">
                            {{ a.label }}
                          </button>
                          <button @click="resetKey(peer.id)" data-testid="device-reset-key"
                            class="mr-2 inline-block px-6 py-2.5 border rounded-md border-primary text-primary hover:bg-primary hover:text-white font-medium">
                            Reset key
                          </button>
                          <a href="javascript:alert('todo')"
                            class="inline-block px-6 py-2.5 border rounded-md border-primary text-primary hover:bg-primary hover:text-white font-medium">
                            Delete
                          </a>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <ListPager :current="list.current.value" :total="list.total.value" :page-size="list.pageSize" @go="list.load" />
              </div>
            </div>
          </div>
        </section>
        <!-- ====== Table Section End -->
</template>
<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import ClipboardButton from './ClipboardButton.vue';
import ListPager from './ListPager.vue';
import { listPeers, resetPeerKey, setPeerAdmission } from '@/utilities/api';
import { usePagedList } from '@/utilities/paged';
import { Admission } from '@/api';

const filter = ref<number | undefined>(undefined);
const list = usePagedList((current, pageSize, q) => listPeers(current, pageSize, q, filter.value));
const admissions = [
    { state: Admission.Admitted, label: 'Admit', testid: 'device-admit' },
    { state: Admission.Rejected, label: 'Reject', testid: 'device-reject' },
    { state: Admission.Pending, label: 'Pending', testid: 'device-pending' },
];

watch(filter, () => list.load(1));

function admit(id: string, admission: Admission): void {
    if (admission === Admission.Rejected && !window.confirm(`Reject device ${id}? Nobody can connect to it.`)) return;
    setPeerAdmission(id, admission)
        .then(() => list.load())
        .catch((error) => window.alert(`Admission of ${id} not changed: ${error?.response?.status ?? error}`));
}

function resetKey(id: string): void {
    if (!window.confirm(`Reset the key of device ${id}? Its next registration sets a new key. Do this only while the device is set up again.`)) return;
    resetPeerKey(id)
        .then(() => window.alert(`Key of ${id} reset.`))
        .catch((error) => window.alert(`Key of ${id} not reset: ${error?.response?.status ?? error}`));
}

onMounted(() => list.load(1));
</script>