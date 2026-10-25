/*!
=========================================================
* © 2024 Ronan LE MEILLAT for SCTG Development
=========================================================
This website use:
- Vite, Vue3, FontAwesome 6, TailwindCss 3
- And many others
*/

import { Configuration, SoftwareApi, UserApi, UserListResponse } from "@/api";
import { GroupApi, Group, PeerApi, Peer, Admission } from '@/api';
import { useUserStore } from "@/stores/sctgDeskStore";

/**
 * The base path for the API.
 * This is the origin of the current window if it is localhost, otherwise it is the origin of the current window.
 * This is need for development purposes.
 */
export const basePath = window.location.origin == "http://localhost:5173" ? "http://127.0.0.1:21114" : window.location.origin;

/** One page of a list endpoint; `total` counts every match. */
export interface Page<T> {
    total: number;
    data: T[];
}

function page<T>(request: Promise<{ data: { total: number, data: T[] } }>): Promise<Page<T>> {
    return request.then((response) => ({ total: response.data.total, data: response.data.data }))
        .catch((error) => {
            console.error(error);
            return { total: 0, data: [] as T[] };
        });
}

/** One page of users ordered by name; `q` matches the name or email. */
export function listUsers(current: number, pageSize: number, q = ""): Promise<Page<UserListResponse>> {
    return page(new UserApi(useUserStore().api_configuration).users(current, pageSize, undefined, undefined, q || undefined));
}

/** One page of groups ordered by name; `q` matches the name. */
export function listGroups(current: number, pageSize: number, q = ""): Promise<Page<Group>> {
    return page(new GroupApi(useUserStore().api_configuration).groups(current, pageSize, q || undefined));
}

/** A choice in a search-backed select. */
export interface Option {
    value: string;
    label: string;
}

/** Up to 50 groups matching `q`, valued by name as user requests expect. */
export function searchGroupNames(q: string): Promise<Option[]> {
    return listGroups(1, 50, q).then((page) => page.data.map((g) => ({ value: g.name, label: g.name })));
}

/** One page of devices ordered by ID; `q` matches the ID or hostname, `admission` is 0 pending, 1 admitted, 2 rejected. */
export function listPeers(current: number, pageSize: number, q = "", admission?: number): Promise<Page<Peer>> {
    return page(new PeerApi(useUserStore().api_configuration).peerList(current, pageSize, undefined, admission, q || undefined));
}

/** Sets the admission state of device `id` (design-device-admission.md). */
export function setPeerAdmission(id: string, admission: Admission): Promise<unknown> {
    return new PeerApi(useUserStore().api_configuration).peerAdmission({ admission }, id);
}

/** Lets device `id` take a new key at its next registration (design-device-key-change.md). */
export function resetPeerKey(id: string): Promise<unknown> {
    return new PeerApi(useUserStore().api_configuration).peerResetKey(id);
}

/**
 * Retrieves the server version.
 * 
 * @return {Promise<string>} A promise that resolves with the server version.
 */
export function getServerVersion(): Promise<string> {
    const configuration = new Configuration({ basePath: basePath });
    const softwareApi = new SoftwareApi(configuration);
    return new Promise<string>((resolve, reject) => {
        softwareApi.softwareVersion().then((response) => {
            if (response.status == 200) {
                resolve(response.data.server);
            }
            else {
                resolve("");
            }
        }).catch((error) => {
            console.error(error);
            resolve("");
        });
    });
}
