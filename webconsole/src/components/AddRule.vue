<!--
=========================================================
* © 2024 Ronan LE MEILLAT for SCTG Development
=========================================================
This website use:
- Vite, Vue3, FontAwesome 6, TailwindCss 3
- And many others
-->
<template>
    <Modal @modal-ok="addRule()" @modal-cancel="cancel" :title="`Add rule for ${props.ab}`">
        <label for="selectedUser" class="block text-sm font-medium text-gray-700">User</label>
        <SearchSelect id="selectedUser" v-model="selectedUser" null-label="Null" :search="searchUsers" />
        <label for="selectedGroup" class="block text-sm font-medium text-gray-700">Group</label>
        <SearchSelect id="selectedGroup" v-model="selectedGroup" null-label="Null" :search="searchGroups" />
        <label for="selectedRights" class="block text-sm font-medium text-gray-700">Rights</label>
        <select if="selectedRights" v-model="selectedRights" class="w-full p-2 border border-gray-300 rounded-md">
            <option v-for="right in rights" :key="right.value" :value="right.value">{{ right.name }}</option>
        </select>
        <span class="text-red-800" v-if="berrorSpanVisible" ref="errorSpan">User must be null for a group rule, group must be null for a user
            rule</span>
    </Modal>
</template>
<script setup lang="ts">
import { ref } from 'vue';
import Modal from './Modal.vue';
import { useUserStore } from '@/stores/sctgDeskStore';
import { listGroups, listUsers, type Option } from '@/utilities/api';
import { AddressBookApi, AbRuleAddRequest } from '@/api';
import SearchSelect from './SearchSelect.vue';

const errorSpan = ref<HTMLSpanElement | null>(null);
const berrorSpanVisible = ref(false);
const props = defineProps<{
    ab: string,
}>()

const rights = [
    { name: 'None', value: '0' },
    { name: 'Read', value: '1' },
    { name: 'Write', value: '2' },
    { name: 'Full Control', value: '3' },
];

const configuration = useUserStore().api_configuration;

const emit = defineEmits(['addRuleOK', 'addRuleCancel'])
const selectedUser = ref<string>('');
const selectedGroup = ref<string>('');
const selectedRights = ref<string>('0');

/**
 * A function that adds a rule based on the selected user, group, and rights.
 *
 * @return {void} This function does not return a value.
 */
function addRule(): void {
    if ((selectedUser.value === '' && selectedGroup.value === '') || (selectedUser.value !== '' && selectedGroup.value !== '')) {
        berrorSpanVisible.value = true;
        return;
    }
    const addressBookApi = new AddressBookApi(configuration);
    const request = {
        guid: props.ab,
        user: selectedUser.value === '' ? null : selectedUser.value,
        group: selectedGroup.value === '' ? null : selectedGroup.value,
        rule: parseInt(selectedRights.value),
    } as AbRuleAddRequest;
    addressBookApi.abRuleAdd(request).then(() => {
        emit('addRuleOK');
    });
}

/**
 * Emits the 'addRuleCancel' event to notify that the rule addition process is canceled.
 *
 * @return {void} This function does not return a value.
 */
function cancel(): void {
    emit('addRuleCancel');
}

function searchUsers(q: string): Promise<Option[]> {
    return listUsers(1, 50, q).then((page) => page.data.map((u) => ({ value: u.guid, label: u.name })));
}

function searchGroups(q: string): Promise<Option[]> {
    return listGroups(1, 50, q).then((page) => page.data.map((g) => ({ value: g.guid, label: g.name })));
}

</script>