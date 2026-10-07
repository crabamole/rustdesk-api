/*!
PKCE (RFC 7636): the verifier stays in this browser tab; the server only sees its S256 hash.
*/

export function randomVerifier(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(48));
    return base64url(bytes);
}

export async function s256Challenge(verifier: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64url(new Uint8Array(digest));
}

function base64url(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
