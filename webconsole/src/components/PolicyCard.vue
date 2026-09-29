<template>
    <section class="bg-white dark:bg-dark">
        <div class="container mx-auto px-4">
            <p class="mb-4 text-sm text-gray-600">
                Settings pushed to every device. They limit what a device allows when someone connects to it,
                not what its user can do on other machines. Devices pick up a change within about 15 seconds;
                a user can change a setting locally afterwards until the policy is saved or re-pushed again.
            </p>
            <div class="max-w-full overflow-x-auto">
                <table class="w-full table-auto">
                    <thead>
                        <tr class="bg-slate-400 text-white">
                            <th class="py-3 px-3 text-left">Setting</th>
                            <th class="py-3 px-3 text-left">Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="k in keys" :key="k.key" class="border-b border-[#E8E8E8]">
                            <td class="py-2 px-3">
                                {{ k.label }} <span class="text-xs text-gray-500">{{ k.key }}</span>
                            </td>
                            <td class="py-2 px-3">
                                <select v-model="choices[k.key]" :data-key="k.key" class="rounded-md border-gray-300">
                                    <option :value="NOT_MANAGED">Not managed</option>
                                    <option value="">Device default</option>
                                    <option v-for="v in k.values" :key="v" :value="v">{{ valueLabel(v) }}</option>
                                </select>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <p class="mt-2 text-xs text-gray-500">
                Not managed leaves devices as they are. Device default resets the setting to the device's built-in default.
            </p>
            <div class="mt-4 flex flex-wrap items-center gap-3">
                <button @click="save" :disabled="keys.length === 0" class="rounded-md bg-slate-600 px-4 py-2 text-white disabled:opacity-50 disabled:cursor-not-allowed">Save</button>
                <button v-if="!confirming" @click="confirming = true" :disabled="keys.length === 0" class="rounded-md bg-black/20 px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed">
                    Re-push to all devices
                </button>
                <span v-else class="flex flex-wrap items-center gap-2">
                    <span class="text-sm">Devices lose local changes to managed settings.</span>
                    <button @click="repush" class="rounded-md bg-red-600 px-3 py-1 text-white">Re-push</button>
                    <button @click="confirming = false" class="rounded-md px-3 py-1">Cancel</button>
                </span>
                <span class="text-sm text-gray-600">Last changed: {{ lastChanged }}</span>
                <span class="text-sm" role="status">{{ message }}</span>
            </div>
        </div>
    </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { PolicyKeyInfo, Strategy, StrategyApi } from '@/api';
import { useUserStore } from '@/stores/sctgDeskStore';
import { NOT_MANAGED, choicesFromOptions, optionsFromChoices, valueLabel } from '@/utilities/policy';

const DEFAULT_STRATEGY = '018f2556-2316-7a02-b31c-5599e7cd5b5e';
const keys = ref([] as PolicyKeyInfo[]);
const choices = ref({} as Record<string, string>);
const modifiedAt = ref(0);
const confirming = ref(false);
const message = ref('');
const lastChanged = computed(() => (modifiedAt.value ? new Date(modifiedAt.value).toLocaleString() : '-'));

function api(): StrategyApi {
    return new StrategyApi(useUserStore().api_configuration);
}

function show(strategy: Strategy): void {
    keys.value = strategy.keys;
    choices.value = choicesFromOptions(strategy.keys.map((k) => k.key), strategy.options);
    modifiedAt.value = strategy.modified_at;
}

function fail(error: any): void {
    console.error(error);
    message.value = `Failed: ${error?.response?.data ?? error}`;
}

onMounted(() => {
    api().strategyGet(DEFAULT_STRATEGY).then((r) => show(r.data)).catch(fail);
});

function save(): void {
    api().strategyUpdate({ options: optionsFromChoices(choices.value) }, DEFAULT_STRATEGY)
        .then((r) => { show(r.data); message.value = 'Saved'; })
        .catch(fail);
}

function repush(): void {
    confirming.value = false;
    api().strategyRepush(DEFAULT_STRATEGY)
        .then((r) => { show(r.data); message.value = 'Re-pushed'; })
        .catch(fail);
}
</script>
