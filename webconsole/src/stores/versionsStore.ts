/*!
=========================================================
* © 2024 Ronan LE MEILLAT for SCTG Development
=========================================================
This website use:
- Vite, Vue3, FontAwesome 6, TailwindCss 3
- And many others
*/

import { getServerVersion } from "@/utilities/api";
import { StoreDefinition, defineStore } from "pinia";

/**
 * The versions store.
 * 
 * @export
 * @type {StoreDefinition<"versions", { serverVersion: string; }, {}, { fetchVersion(): Promise<void>; }>}
 * @property {string} serverVersion The server version.
 */
export const useVersionsStore: StoreDefinition<"versions", {
    serverVersion: string | null;
}, {}, {
    fetchVersions(): Promise<void>;
}> = defineStore('versions', {
    state: () => ({
        serverVersion: null as string,
    }),
    actions: {
        async fetchVersions() {
            // console.log("Fetching versions");
            if (!this.serverVersion) {
                this.serverVersion = await getServerVersion();
            }
        }
    }
});