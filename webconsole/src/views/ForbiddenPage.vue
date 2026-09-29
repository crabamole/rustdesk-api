<template>
    <div class="flex min-h-full flex-1 flex-col justify-center px-6 py-12 lg:px-8">
        <div class="sm:mx-auto sm:w-full sm:max-w-sm text-center">
            <p class="text-5xl font-bold text-gray-400">403</p>
            <h2 class="mt-4 text-2xl font-bold leading-9 tracking-tight text-gray-900">You are not an admin</h2>
            <p class="mt-2 text-sm text-gray-600">
                Signed in as {{ userStore.user?.name }}. This console is for administrators only.
            </p>
            <button @click="signOut"
                class="mt-8 flex w-full h-12 items-center justify-center rounded-md bg-gray-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-gray-500">
                Sign out
            </button>
        </div>
    </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router';
import { LoginApi } from '@/api';
import { useUserStore } from '@/stores/sctgDeskStore';

const userStore = useUserStore();
const router = useRouter();

function signOut(): void {
    const loginApi = new LoginApi(userStore.api_configuration);
    // Leave the console even if the server call fails; the session then just expires.
    loginApi.logout({ id: userStore.user?.name ?? '', uuid: '' })
        .catch((error) => console.error(error))
        .finally(() => {
            userStore.user = null;
            userStore.api_configuration = null;
            router.push({ name: 'login' });
        });
}
</script>
