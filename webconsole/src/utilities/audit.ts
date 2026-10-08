/*!
Labels for audit log codes (audit-api-spec §3.2, §5, §6) and login outcomes.
*/

export const CONN_TYPES: Record<number, string> = {
    0: 'Remote desktop', 1: 'File transfer', 2: 'Port forward', 3: 'View camera', 4: 'Terminal',
};

export function connTypeLabel(t?: number): string {
    return t === undefined || t === null ? 'Not logged in' : CONN_TYPES[t] ?? `Unknown (${t})`;
}

const PRIMARY_AUTH: Record<number, string> = { 1: 'Click to accept', 2: 'One-time password', 3: 'Permanent password', 4: 'Switch sides' };
const TWO_FACTOR: Record<number, string> = { 1: '2FA code', 2: 'Trusted device' };

export function authLabel(primary?: number, twoFactor?: number): string {
    const parts = [primary ? PRIMARY_AUTH[primary] ?? `Unknown (${primary})` : '', twoFactor ? TWO_FACTOR[twoFactor] ?? `Unknown (${twoFactor})` : ''];
    return parts.filter(Boolean).join(' + ');
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
