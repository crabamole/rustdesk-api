<!--
=========================================================
* © 2024 Ronan LE MEILLAT for SCTG Development
=========================================================
This website use:
- Vite, Vue3, FontAwesome 6, TailwindCss 3
- And many others
-->
<template>
    <div class="flex min-h-full flex-1 flex-col justify-center px-6 py-12 lg:px-8">
        <div class="sm:mx-auto sm:w-full sm:max-w-sm">
            <img class="mx-auto h-10 w-auto" :src="$require('@/assets/sctg.svg')" alt="Your Company" />
            <h2 class="mt-10 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">rustdesk-api v{{
                serverVersion }}</h2>
        </div>

        <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
            <p id="loginResult" class="text-center text-sm text-red-700"></p>
            <div>
                <div class="pt-1.5" v-for="oauthprovider in oauthproviders">
                    <button @click="oidcAuth_step1(oauthprovider)"
                        class="flex w-full h-12 items-center justify-center rounded-md bg-gray-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-gray-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600">Sign
                        in with {{ capitalizeFirstLetter(oauthprovider.name) }}</button>
                </div>
            </div>
        </div>
    </div>
</template>
<script setup lang="ts">
import { $require, generateUUIDBase64Encoded } from '@/utilities/viteHelper.js'
import { useUserStore } from '@/stores/sctgDeskStore';
import { useRouter } from 'vue-router';
import { onMounted, ref } from 'vue';
import { LoginApi, Configuration } from '@/api';
import { useVersionsStore } from '@/stores/versionsStore';
import { basePath } from '@/utilities/api';
import { randomVerifier, s256Challenge } from '@/utilities/pkce';

const serverVersion = ref("");

const userStore = useUserStore();
const router = useRouter();

type OauthProvider = {
    name: string;
    rustdesk_name: string;
};

const oauthproviders = ref([] as OauthProvider[]);

/**
 * Sets the inner text of the element with the ID "loginResult" to the specified message.
 *
 * @param {string} message - The message to be displayed.
 * @return {void} This function does not return a value.
 */
function setLoginResult(message: string): void {
    document.getElementById("loginResult").innerText = message;
}

/**
 * Performs the first step of the OIDC authentication process.
 *
 * @param {OauthProvider} provider - The OauthProvider object representing the chosen provider.
 * @return {Promise<void>} - A promise that resolves when the authentication process is complete.
 */
async function oidcAuth_step1(provider: OauthProvider) {
    const configuration = new Configuration({
        basePath: basePath,
    });
    const loginApi = new LoginApi(configuration);
    const verifier = randomVerifier();
    const oidcAuthRequest = {
        deviceInfo: {
            name: navigator.appName,
            os: navigator.platform,
            type: "oidc",
        },
        id: userStore.id,
        op: provider.rustdesk_name,
        uuid: userStore.uuid_base64,
        returnTo: window.location.origin + '/ui/login',
        codeChallenge: await s256Challenge(verifier),
    }
    loginApi.oidcAuth(oidcAuthRequest).then((response) => {
        if (!response.data.url) {
            setLoginResult("OIDC provider not configured");
            return;
        }
        sessionStorage.setItem('oidc_id', userStore.id);
        sessionStorage.setItem('oidc_uuid', userStore.uuid_base64);
        sessionStorage.setItem('oidc_verifier', verifier);
        window.location.href = response.data.url;
    }).catch((error) => {
        console.log(error);
        setLoginResult("OIDC authentication failed");
    });
}

function handleOidcResult(result: string) {
    const id = sessionStorage.getItem('oidc_id');
    const uuid = sessionStorage.getItem('oidc_uuid');
    sessionStorage.removeItem('oidc_id');
    const verifier = sessionStorage.getItem('oidc_verifier');
    sessionStorage.removeItem('oidc_uuid');
    sessionStorage.removeItem('oidc_verifier');
    if (!id || !uuid || !verifier) {
        setLoginResult("OIDC session expired, please try again");
        return;
    }
    const configuration = new Configuration({ basePath: basePath });
    const loginApi = new LoginApi(configuration);
    loginApi.oidcToken({ result, codeVerifier: verifier, id, uuid }).then((response) => {
        if (response.data.access_token !== undefined) {
            userStore.user = {
                name: response.data.user.name,
                admin: response.data.user.is_admin,
                email: response.data.user.email,
            };
            userStore.api_configuration = configuration;
            userStore.api_configuration.accessToken = response.data.access_token;
            router.push({ name: 'index' });
        } else {
            setLoginResult("OIDC login failed");
        }
    }).catch((error) => {
        console.log(error);
        setLoginResult("OIDC login failed");
    });
}

/**
 * Capitalizes the first letter of a given string.
 *
 * @param {string} string - The string to capitalize.
 * @return {string} The capitalized string.
 */
function capitalizeFirstLetter(string: string): string {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

onMounted(() => {
    useVersionsStore().fetchVersions().then(() => {
        serverVersion.value = useVersionsStore().serverVersion;
    })
    userStore.uuid_base64 = generateUUIDBase64Encoded();
    userStore.id = Math.random().toString(36).substring(2, 15);

    const params = new URLSearchParams(window.location.search);
    const oidcResult = params.get('result');
    const oidcError = params.get('error');
    if (oidcResult) {
        window.history.replaceState({}, '', window.location.pathname);
        handleOidcResult(oidcResult);
        return;
    }
    if (oidcError) {
        window.history.replaceState({}, '', window.location.pathname);
        setLoginResult("OIDC login failed");
    }

    const configuration = new Configuration({
        basePath: basePath,
    });
    const loginApi = new LoginApi(configuration);
    loginApi.loginOptions().then((_providers) => {
        for (const _provider of _providers.data) {
            oauthproviders.value.push({
                name: _provider.split("/")[1],
                rustdesk_name: _provider.split("/")[1]
            });
        }
    }).catch((error) => {
        console.log(error);
    });
})
</script>