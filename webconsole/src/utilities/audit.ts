/*!
Labels for audit log codes (audit-api-spec §3.2, §5, §6) and login outcomes.
*/

export const CONN_TYPES: Record<number, string> = {
    0: 'Remote desktop', 1: 'File transfer', 2: 'Port forward', 3: 'View camera', 4: 'Terminal',
};

export function connTypeLabel(t?: number): string {
    return t === undefined || t === null ? 'Not logged in' : CONN_TYPES[t] ?? `Unknown (${t})`;
}

const PRIMARY_AUTH: Record<number, string> = { 1: 'Click to accept', 2: 'One-time password', 3: 'Permanent password', 4: 'Switch sides', 5: 'Same user' };
const TWO_FACTOR: Record<number, string> = { 1: '2FA code', 2: 'Trusted device' };

export function authLabel(primary?: number, twoFactor?: number): string {
    const parts = [primary ? PRIMARY_AUTH[primary] ?? `Unknown (${primary})` : '', twoFactor ? TWO_FACTOR[twoFactor] ?? `Unknown (${twoFactor})` : ''];
    return parts.filter(Boolean).join(' + ');
}

const CONSOLE_AREAS: Record<number, string> = { 0: 'Group', 1: 'User', 2: 'Device', 3: 'Address book', 4: 'Policy' };
const CONSOLE_ACTIONS: Record<number, string> = {
    1: 'Add group', 2: 'Add user', 4: 'Delete groups', 5: 'Disconnect', 6: 'Enable users', 7: 'Disable users',
    10: 'Update group', 11: 'Update user', 13: 'Delete user', 15: 'Add address book', 16: 'Delete address book',
    17: 'Rename address book', 20: 'Add address book permission', 21: 'Delete address book permission',
    23: 'Promote admin', 24: 'Demote admin', 25: 'Update policy', 26: 'Re-push policy', 27: 'Reset device key', 28: 'Device key changed',
};

export function consoleAreaLabel(typ: number): string {
    return CONSOLE_AREAS[typ] ?? `Unknown (${typ})`;
}

export function consoleActionLabel(iop: number): string {
    return CONSOLE_ACTIONS[iop] ?? `Unknown (${iop})`;
}

/** A user reference `{guid, name, email}` as "name <email>". */
function userRef(u: any): string {
    if (!u || typeof u !== 'object' || !('guid' in u)) return JSON.stringify(u);
    return u.email ? `${u.name ?? u.guid} <${u.email}>` : (u.name ?? u.guid);
}

/** `info` as `key: value` pairs; user references by name; other objects and lists as compact JSON. */
export function consoleDetails(info: any): string {
    if (!info || typeof info !== 'object') return info == null ? '' : String(info);
    return Object.entries(info).map(([k, v]) => {
        if (k === 'users' && Array.isArray(v)) return `${k}: ${v.map(userRef).join(', ')}`;
        if (k === 'user' && v && typeof v === 'object') return `${k}: ${userRef(v)}`;
        return `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`;
    }).join(', ');
}

const ALARMS: Record<number, string> = {
    0: 'Access outside the IP whitelist', 1: 'Over 30 consecutive access attempts', 2: 'Multiple access attempts within one minute',
    6: 'Too many attempts from an IPv6 prefix', 7: 'Terminal login backoff', 8: 'Terminal login busy',
    9: 'Session scope violation', 10: 'Access outside the ID whitelist',
};

export function alarmLabel(t: number): string {
    return ALARMS[t] ?? `Unknown (${t})`;
}

export function machineLabel(hostname?: string | null, os?: string | null, loginIp?: string | null): string {
    if (!hostname) return '';
    const machine = os ? `${hostname} (${os})` : hostname;
    return loginIp ? `${machine}, logged in from ${loginIp}` : machine;
}

export const LOGIN_OUTCOMES: Record<string, string> = {
    ok: 'Signed in', idp_denied: 'Denied at the identity provider', idp_error: 'Identity provider error',
    inactive: 'Account not activated', refused: 'Refused',
};

export function loginOutcomeLabel(o: string): string {
    return LOGIN_OUTCOMES[o] ?? o;
}

const LOGIN_CLIENTS: Record<string, string> = { native: 'Native client', web: 'Web client', console: 'Console' };

export function loginClientLabel(c: string): string {
    return LOGIN_CLIENTS[c] ?? c;
}

export function fileDirectionLabel(t: number): string {
    return t === 1 ? 'Upload to device' : 'Download from device';
}

export function formatTime(unixSeconds?: number): string {
    return unixSeconds ? new Date(unixSeconds * 1000).toLocaleString() : '';
}

/** audits.py convention: plain text becomes a contains-match. */
export function likePattern(text: string): string | undefined {
    const t = text.trim();
    return t === '' ? undefined : t.includes('%') ? t : `%${t}%`;
}
