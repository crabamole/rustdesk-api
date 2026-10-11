import { computed, ref, watch } from 'vue';
import type { Page } from '@/utilities/api';

/** Server-side paging and search for a console table: `load(n)` fetches page n of the current search. */
export function usePagedList<T>(fetch: (current: number, pageSize: number, q: string) => Promise<Page<T>>, pageSize = 20) {
    const items = ref([] as T[]);
    const total = ref(0);
    const current = ref(1);
    const q = ref("");
    const pages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)));

    function load(n = current.value): Promise<void> {
        const search = q.value;
        return fetch(n, pageSize, search).then((page) => {
            // A slower reply for an older search must not overwrite the newer one.
            if (search !== q.value) return;
            items.value = page.data;
            total.value = page.total;
            current.value = n;
        });
    }

    let timer: ReturnType<typeof setTimeout> | undefined;
    watch(q, () => {
        clearTimeout(timer);
        timer = setTimeout(() => load(1), 300);
    });

    return { items, total, current, pages, q, pageSize, load };
}
