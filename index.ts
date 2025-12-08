//
// Polyfill
//

if (typeof globalThis.crypto?.subtle === 'undefined') {
    throw new Error('WebCrypto (crypto.subtle) is required for DPoP. Provide a polyfill or use a modern browser.');
}

if (typeof TextEncoder === 'undefined') {
    throw new Error('TextEncoder is required.');
}

/**
 * Extend Uint8Array prototype to include the new toBase64 method.
 */
interface Uint8Array {
    toBase64(options?: {
        alphabet?: 'base64' | 'base64url';
        omitPadding?: boolean;
    }): string;
}

/**
 * Polyfill for Uint8Array.prototype.toBase64()
 *
 * @link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array/toBase64
 */
if (typeof Uint8Array.prototype.toBase64 !== 'function') {

    // Define the custom method on the prototype
    Uint8Array.prototype.toBase64 = function (options = {}) {
        const CHUNK_SIZE = 0x8000; // 32k

        let binary = ''
        for (let i = 0; i < this.length; i += CHUNK_SIZE) {
            const chunk = this.subarray(i, i + CHUNK_SIZE)
            binary += String.fromCharCode.apply(null, chunk)
        }

        let base64 = globalThis.btoa(binary)

        if (options.alphabet === 'base64url') {
            base64 = base64.replace(/\+/g, '-').replace(/\//g, '_')
        }
        if (options.omitPadding) {
            base64 = base64.replace(/=+$/, '')
        }
        return base64
    }

    console.warn('Polyfill applied: Uint8Array.prototype.toBase64.')
}

//
// Helper functions
//

/**
 * Converts a JavaScript object to a Base64URL-encoded string.
 *
 * Caution! The function doesn't guarantee lexicographical sorting.
 * DO NOT USE for JWK thumbprint.
 */
function base64UrlEncodeJson(data: any): string {
    const jsonString = JSON.stringify(data)
    const uint8Array = new TextEncoder().encode(jsonString)

    return uint8Array.toBase64({
        alphabet: 'base64url',
        omitPadding: true,
    })
}

/**
 * Hashes raw string data using SHA-256 and Base64URL-encodes the result.
 */
async function sha256Base64Url(data: string): Promise<string> {
    const buffer = await globalThis.crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(data)
    );

    return new Uint8Array(buffer).toBase64({
        alphabet: 'base64url',
        omitPadding: true,
    });
}

function extractDPoPNonce(headers: Headers): string | null {
    if (!headers.has('DPoP-Nonce')) {
        return null
    }

    return headers.get('DPoP-Nonce').trim() || null
}

/**
 * Creates and signs a DPoP Proof JWT for a given request.
 * @param {DPoPKey} dpopKey The DPoP key data used to sign the proof.
 * @param {string} htm The HTTP method (e.g., "GET").
 * @param {string} htu The HTTP URL.
 * @param {string|null} accessToken Optional. The access token value if present.
 * @param {string|null} nonce Optional. Server-provided nonce for replay protection.
 * @returns {Promise<string>} The complete DPoP Proof JWT string.
 */
async function createDPoPJwt(
    dpopKey: DPoPKey,
    htm: string,
    htu: string,
    accessToken: string | null = null,
    nonce: string | null = null
): Promise<string> {
    // 1. Prepare JWT Header
    const header = {
        'typ': 'dpop+jwt',
        'alg': 'ES256', // Matches P-256 curve
        'jwk': dpopKey.dpopJwk,
    }

    // 2. Prepare JWT Claims (Payload)
    const claims: {
        jti: string;
        htm: string;
        htu: string;
        iat: number;
        ath?: string;
        nonce?: string;
    } = {
        'jti': globalThis.crypto.randomUUID(),    // Unique JWT ID to prevent replay attacks
        'htm': htm.toUpperCase(),                 // HTTP Method (normalized to uppercase)
        'htu': DPoPUrlNormalizer.normalizeUrl(htu),   // Normalized HTTP URL
        'iat': Math.floor(Date.now() / 1000),     // Issued At timestamp
    }

    // Include 'ath' (Access Token Hash) if an access token is provided
    if (accessToken) {
        claims.ath = await sha256Base64Url(accessToken);
    }

    // Include 'nonce' if provided by the server
    if (nonce) {
        claims.nonce = nonce;
    }

    // 3. Create the Signing Input
    const encodedHeader = base64UrlEncodeJson(header)
    const encodedClaims = base64UrlEncodeJson(claims)
    const jwsSigningInput = `${encodedHeader}.${encodedClaims}`

    // 4. Sign the Input with the Private Key
    const signature = await dpopKey.sign(jwsSigningInput)

    // 5. Base64URL-encode the Signature
    const encodedSignature = new Uint8Array(signature).toBase64(
        {alphabet: 'base64url', omitPadding: true},
    )

    // 6. Return the complete DPoP Proof JWT
    return `${jwsSigningInput}.${encodedSignature}`
}

//
// DPoP KEY AND PERSISTENCE
//

interface DPoPKeyStore {
    store(dpopKey: DPoPKey): Promise<void>

    load(): Promise<DPoPKey | null>

    delete(): Promise<void>
}

const DPOP_DB_NAME = 'DPoPKeyStore'
const DPOP_STORE_NAME = 'KeyObjects'
const DPOP_KEY_NAME = 'dpop_key_data'

class IndexedDBKeyStore implements DPoPKeyStore {
    constructor(
        public dbName: string = DPOP_DB_NAME,
        public storeName: string = DPOP_STORE_NAME,
        public keyName: string = DPOP_KEY_NAME
    ) {
    }

    /**
     * Opens a connection to IndexedDB.
     */
    private open() {
        return new Promise<IDBDatabase>((resolve, reject) => {
            const request = indexedDB.open(this.dbName, 1)

            // Create the object store if it doesn't exist
            request.onupgradeneeded = (event: IDBVersionChangeEvent): void => {
                const db = (event.target as IDBOpenDBRequest).result

                db.createObjectStore(this.storeName)
            }

            request.onsuccess = (event: Event): void => {
                resolve((event.target as IDBOpenDBRequest).result)
            }

            request.onerror = (event: Event): void => {
                const target = event.target as IDBRequest
                const error: DOMException | null = target.error

                if (error) {
                    reject(`IndexedDB error: ${error.name} - ${error.message}`)
                } else {
                    reject('An unknown IndexedDB error occurred.')
                }
            }
        })
    }

    async store(dpopKey: DPoPKey): Promise<void> {
        const db = await this.open()

        return new Promise<void>((resolve, reject) => {
            const transaction = db.transaction([this.storeName], 'readwrite');
            const store = transaction.objectStore(this.storeName);
            try {
                const request = store.put(dpopKey, this.keyName);
                request.onsuccess = () => resolve();
                request.onerror = (event) => reject((event.target as IDBRequest).error);
            } catch (err) {
                // Structured clone of CryptoKey may not be supported.
                console.warn('Failed to persist CryptoKey to IndexedDB; continuing with ephemeral key.', err);
                resolve(); // resolve but key isn't persisted — caller should be aware
            }
        }).finally(() => db.close())
    }

    async load(): Promise<DPoPKey | null> {
        const db = await this.open()

        return new Promise<DPoPKey | null>((resolve, reject) => {
            const transaction = db.transaction([this.storeName], 'readonly')
            const store = transaction.objectStore(this.storeName)
            const request = store.get(this.keyName)

            request.onsuccess = () => resolve(request.result)
            request.onerror = (event) => reject((event.target as IDBRequest).error)
        }).finally(() => db.close())
    }

    async delete(): Promise<void> {
        const db = await this.open()

        return new Promise<void>((resolve, reject) => {
            const transaction = db.transaction([this.storeName], 'readwrite')
            const store = transaction.objectStore(this.storeName)
            const request = store.delete(this.keyName)

            request.onsuccess = () => resolve()
            request.onerror = (event) => reject((event.target as IDBRequest).error)
        }).finally(() => db.close())
    }
}

/**
 * Provides a DPoPKey.
 *
 * Encapsulates the DPoP key generation and persistence logic.
 */
class DPoPKeyProvider {
    constructor(
        private store: DPoPKeyStore = new IndexedDBKeyStore()
    ) {
    }

    private generatingPromise: Promise<DPoPKey> | null = null;

    /**
     * Returns the existing key or generate a new one.
     * @returns {Promise<DPoPKey>} The active DPoPKey instance.
     */
    async provideKey(): Promise<DPoPKey> {
        const existing = await this.load();
        if (existing) return existing;

        // in-process mutex to avoid race conditions while no key exists.
        if (this.generatingPromise) return this.generatingPromise
        this.generatingPromise = this.generateAndStoreNew().finally(() => {
            this.generatingPromise = null
        })

        return this.generatingPromise
    }

    /**
     * Rotates the DPoP key by generating a new one and storing it.
     * @returns {Promise<DPoPKey>} The new DPoPKey instance.
     */
    async rotateKey(): Promise<DPoPKey> {
        console.log('Rotating DPoP key...')
        await this.store.delete()
        return await this.generateAndStoreNew()
    }

    /**
     * Loads the key instance from IndexedDB.
     */
    private async load(): Promise<DPoPKey | null> {
        const loaded = await this.store.load();
        if (!loaded) return null;

        // Basic shape checks
        if (!loaded.dpopJwk || !loaded.jkt || !loaded.privateKey) {
            console.warn('DPoPKey missing required fields — ignoring stored key.');
            return null;
        }

        // Sanitize: canonicalize the public JWK we just read
        let canonicalJwk: JsonWebKey;
        try {
            canonicalJwk = this.canonicalizeEcPublicJwk(loaded.dpopJwk);
        } catch (err) {
            console.warn('Stored JWK invalid — regenerating key.', err);
            return null;
        }

        // Recompute jkt and compare
        const canonicalForThumbprint = JSON.stringify({
            crv: canonicalJwk.crv,
            kty: canonicalJwk.kty,
            x: canonicalJwk.x,
            y: canonicalJwk.y,
        });
        const recomputedJkt = await sha256Base64Url(canonicalForThumbprint);
        if (recomputedJkt !== loaded.jkt) {
            console.warn('Stored jkt mismatch — stored key appears tampered. Regenerating.');
            return null;
        }

        // All good — reconstruct DPoPKeyData using canonicalized JWK.
        return new DPoPKey(loaded.privateKey, canonicalJwk, loaded.jkt, loaded.createdAt);
    }

    /**
     * Generates a new key pair and stores it.
     */
    private async generateAndStoreNew(): Promise<DPoPKey> {
        console.log('Generating a new DPoP Key…')

        const {privateKey, dpopJwk, jkt} = await this.generateComponents()
        const keyData = new DPoPKey(privateKey, dpopJwk, jkt, Date.now())
        await this.store.store(keyData)

        return keyData
    }

    /**
     * Generates components for a new DPoP key (private key, public JWK, JWK thumbprint).
     */
    private async generateComponents(): Promise<{
        privateKey: CryptoKey,
        dpopJwk: JsonWebKey,
        jkt: string
    }> {
        // 1. Define key parameters
        const algorithm = {
            name: 'ECDSA',
            namedCurve: 'P-256', // Recommended curve for DPoP/ES256
        }
        const keyUsages = ['sign', 'verify'] as KeyUsage[];

        // 2. Generate the non-extractable key pair
        const keyPair = await globalThis.crypto.subtle.generateKey(
            algorithm,
            false, // Non-extractable for security
            keyUsages,
        )

        // 3. Export the public key as a JWK (JSON Web Key)
        const exportedKey = await globalThis.crypto.subtle.exportKey('jwk', keyPair.publicKey)
        const dpopJwk = this.canonicalizeEcPublicJwk(exportedKey as JsonWebKey)

        // 4. Calculate the 'jkt' (JSON Web Key Thumbprint)
        // Per RFC 7638, the JWK must be cleaned of private claims, and keys must be
        // serialized in strict lexicographical order for the SHA-256 hash.
        const canonicalForThumbprint = JSON.stringify({
            crv: dpopJwk.crv,
            kty: dpopJwk.kty,
            x: dpopJwk.x,
            y: dpopJwk.y,
        })

        const jkt = await sha256Base64Url(canonicalForThumbprint);

        return {
            privateKey: keyPair.privateKey,
            dpopJwk,
            jkt,
        }
    }

    private canonicalizeEcPublicJwk(jwk: JsonWebKey): JsonWebKey {
        if (!jwk || jwk.kty !== 'EC') {
            throw new Error('Expected EC public JWK');
        }
        // Only include the required public fields in a deterministic order.
        return {
            crv: jwk.crv,
            kty: jwk.kty,
            x: jwk.x,
            y: jwk.y,
        };
    }
}

const DEFAULT_KEY_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

/**
 * A Demonstration of Proof-of-Possession (DPoP) key consisting of: private key, public JWK, JWK thumbprint (jkt), and timestamp.
 */
class DPoPKey {
    /**
     * @param {CryptoKey} privateKey - The non-extractable private key object.
     * @param {JsonWebKey} dpopJwk - The public key in JWK format for the DPoP header.
     * @param {string} jkt - The Base64URL-encoded SHA-256 thumbprint of the public key.
     * @param {number} createdAt - Timestamp when the key was created.
     */
    constructor(
        public readonly privateKey: CryptoKey,
        public readonly dpopJwk: JsonWebKey,
        public readonly jkt: string,
        public readonly createdAt: number = Date.now()
    ) {
        if (!privateKey || !dpopJwk || !jkt) {
            throw new Error(
                'DPoPKey requires privateKey, dpopJwk, and jkt to be provided.')
        }
    }

    /**
     * Signs the given input string using the private key.
     * @param {string} input The input string to sign.
     * @returns {Promise<ArrayBuffer>} The signature as an ArrayBuffer.
     */
    public async sign(input: string): Promise<ArrayBuffer> {
        // 1. Get the raw signature (could be DER or R||S format)
        const rawSignature = await globalThis.crypto.subtle.sign(
            {name: 'ECDSA', hash: {name: 'SHA-256'}},
            this.privateKey,
            new TextEncoder().encode(input),
        );

        // 2. Normalize to the fixed-length R||S (JOSE) format
        return this.derToJose(rawSignature, 32);
    }

    /**
     * Ensures that no matter which browser provides which signature encoding,
     * the final JWS/DPoP JWT signature is always valid ES256-JOSE format.
     */
    private derToJose(signature: ArrayBuffer, keySize: number = 32): ArrayBuffer {
        const bytes = new Uint8Array(signature);

        // If already raw (R||S) length -> return.
        if (bytes.length === keySize * 2) {
            return signature;
        }

        let offset = 0;
        if (bytes[offset++] !== 0x30) {
            throw new Error('Invalid DER signature: expected SEQUENCE');
        }

        // Read SEQUENCE length (support multi-byte)
        let seqLen = bytes[offset++];
        if (seqLen & 0x80) {
            const n = seqLen & 0x7f;
            seqLen = 0;
            for (let i = 0; i < n; i++) {
                seqLen = (seqLen << 8) | bytes[offset++];
            }
        }

        // Read INTEGER (R)
        if (bytes[offset++] !== 0x02) {
            throw new Error('Invalid DER signature: expected INTEGER for R');
        }
        let rLen = bytes[offset++];
        if (rLen & 0x80) {
            const n = rLen & 0x7f;
            rLen = 0;
            for (let i = 0; i < n; i++) {
                rLen = (rLen << 8) | bytes[offset++];
            }
        }
        let r = bytes.subarray(offset, offset + rLen);
        offset += rLen;

        // Read INTEGER (S)
        if (bytes[offset++] !== 0x02) {
            throw new Error('Invalid DER signature: expected INTEGER for S');
        }
        let sLen = bytes[offset++];
        if (sLen & 0x80) {
            const n = sLen & 0x7f;
            sLen = 0;
            for (let i = 0; i < n; i++) {
                sLen = (sLen << 8) | bytes[offset++];
            }
        }
        let s = bytes.subarray(offset, offset + sLen);

        // Remove leading zeros if present
        if (r[0] === 0x00 && r.length > keySize) r = r.subarray(1);
        if (s[0] === 0x00 && s.length > keySize) s = s.subarray(1);

        const raw = new Uint8Array(keySize * 2);
        raw.set(r, keySize - r.length);
        raw.set(s, keySize + (keySize - s.length));
        return raw.buffer;
    }

    /**
     * Checks if the key should be rotated based on age.
     * @param {number} maxAgeMs Maximum age in milliseconds
     * @returns {boolean} True if the key should be rotated
     */
    public shouldRotate(maxAgeMs: number = DEFAULT_KEY_MAX_AGE_MS): boolean {
        return Date.now() - this.createdAt > maxAgeMs
    }
}

//
// HTU
//

class DPoPUrlNormalizer {
    /**
     * Resolves a request input.
     */
    public static normalizeRequestInput(input: RequestInfo | URL | string) {
        const requestUrl: URL = DPoPUrlNormalizer.resolveUrl(input)

        return DPoPUrlNormalizer.normalizeUrl(requestUrl.href)
    }

    /**
     * Normalizes an HTTP URL for the 'htu' claim according to DPoP specification.
     * - Converts scheme and host to lowercase
     * - Removes default ports (80 for http, 443 for https)
     * - Removes query string and fragment
     * @param {string} url The URL to normalize
     * @returns {string} The normalized URL
     */
    public static normalizeUrl(url: string): string {
        const parsed = new URL(url)

        const scheme = parsed.protocol.slice(0, -1).toLowerCase()
        const host = parsed.hostname.toLowerCase()

        let port = parsed.port
        if ((scheme === 'https' && port === '443') ||
            (scheme === 'http' && port === '80')) {
            port = ''
        }

        const portPart = port ? `:${port}` : ''
        return `${scheme}://${host}${portPart}${parsed.pathname}`
    }

    /**
     * Resolves the input of a fetch into a URL object.
     */
    private static resolveUrl(input: RequestInfo | URL | string) {
        if (input instanceof URL) {
            return input;
        }

        if (input instanceof Request) {
            return new URL(input.url);
        }

        // Use a try-catch block to handle absolute vs. relative URLs
        try {
            // Try to parse as an absolute URL first
            return new URL(input);
        } catch (e) {
            // If it fails (it's a relative URL), resolve it against the current window's location
            return new URL(input, window.location.href);
        }
    }
}

//
// DPoP Signer
//

/**
 * Options for DPoP signing.
 */
interface DPoPSignOptions {
    accessToken?: string | null;
    nonce?: string | null;
}

class DPoPSigner {
    /**
     * Stores the next expected DPoP nonce, keyed by the normalized HTTP URL (htu).
     *
     * This cache is critical for two purposes:
     *
     * 1. Proactive Use: It stores a new nonce received on a successful 200 OK
     * response (from either the token or resource endpoint) for the *next* request
     * to the same resource, preventing a mandatory 401 challenge.
     *
     * 2. Challenge-Response Staging: It acts as the temporary staging area for a nonce
     * received during a 401 Unauthorized challenge. When a challenge occurs,
     * the decorator stores the new nonce here, allowing the signProof method to
     * reliably pull it for the immediate retry attempt.
     *
     * Note: Nonces are single-use, so entries are invalidated on successful consumption.
     * The htu key ensures correct nonce isolation across different API endpoints.
     */
    private nonceCache: Map<string, string> = new Map();

    /**
     * Stores a one-shot global nonce for the *very next* request only.
     * Not keyed by HTU. Used for challenge-response and post-token optimization.
     */
    private oneShotNonce: string | null = null

    constructor(
        private provider: DPoPKeyProvider = new DPoPKeyProvider()
    ) {
    }

    /**
     * Signs a DPoP Proof for the given request.
     * @param {RequestInfo|URL|string} input The request URL or Request object.
     * @param {string} method The HTTP method (e.g., "GET").
     * @param {DPoPSignOptions} options Optional parameters to sign the proof.
     * @returns {Promise<string>} The complete DPoP Proof JWT string.
     */
    public async signProof(
        input: RequestInfo | URL | string,
        method: string,
        options: DPoPSignOptions = {}
    ): Promise<string> {
        const htu = DPoPUrlNormalizer.normalizeRequestInput(input)

        // Consume the stored nonce atomically so parallel calls cannot both use it.
        let nonce = options.nonce
        if (!nonce) {
            const stored = this.oneShotNonce
            if (stored !== null) {
                // Only the thread that sees non-null consumes it.
                nonce = stored
                this.oneShotNonce = null
            }
        }

        // Atomically claim nonce synchronously before any await.
        if (!nonce) {
            nonce = this.nonceCache.get(htu)
            this.nonceCache.delete(htu)
        }

        // To avoid race conditions, it's IMPORTANT for `await` to be AFTER the nonce claim.
        const dpopKey = await this.provider.provideKey()

        return createDPoPJwt(dpopKey, method, htu, options.accessToken || null, nonce || null)
    }

    /**
     * Stores a nonce received from the server for a specific endpoint.
     * @param {string} endpoint The endpoint URL
     * @param {string} nonce The nonce value
     */
    public setNonce(endpoint: string, nonce: string): void {
        this.nonceCache.set(endpoint, nonce)
    }

    /**
     * Sets the one-shot global nonce for the next request that doesn't define one.
     * @param {string} nonce The nonce value
     */
    public setOneShotNonce(nonce: string): void {
        this.oneShotNonce = nonce
    }

    /**
     * Clears the nonce for a specific endpoint.
     * @param {string} endpoint The endpoint URL
     */
    public clearNonce(endpoint: string): void {
        this.nonceCache.delete(endpoint)
    }

    /**
     * Rotates the DPoP key if needed based on age.
     */
    public async rotateKeyIfNeeded(): Promise<void> {
        const dpopKey = await this.provider.provideKey()
        if (dpopKey.shouldRotate()) {
            await this.provider.rotateKey()
            console.log('DPoP key rotated due to age')
        }
    }
}

//
// DPoP `fetch` decorator.
//

/**
 * Decorates the `fetch` function to add DPoP support.
 * @param {Function} fetch The fetch function to decorate.
 * @param {DPoPSigner} signer The DPoP proof signer.
 * @param {Function} getAccessToken A function that returns the access token to use for requests.
 */
function createDPoPFetch(
    fetch: (input: RequestInfo | URL, init?: RequestInit | null) => Promise<Response>,
    signer: DPoPSigner,
    getAccessToken: () => string | null,
) {
    return async (
        input: RequestInfo | URL,
        init?: RequestInit | null
    ): Promise<Response> => {
        console.debug("fetching: ", input, " with init:", init)

        try {
            const method = init?.method || 'GET'
            const headers = new Headers(init?.headers || {})
            const accessToken = getAccessToken()

            // Generate DPoP proof
            const dpopProof = await signer.signProof(input, method, {accessToken})

            // Add Authorization header if access token is provided
            if (accessToken) {
                // DPoP tokens MUST use the DPoP type
                headers.set('Authorization', 'DPoP ' + accessToken)
            }

            headers.set('DPoP', dpopProof)

            // First attempt
            let response = await fetch(input, {
                ...init,
                method: method,
                headers: headers,
            })

            let nonce = extractDPoPNonce(response.headers)

            // Handle DPoP nonce requirement (status 401)
            if (response.status === 401 && nonce) {
                // Retry the request with the nonce
                const retryProof = await signer.signProof(input, method, {
                    accessToken,
                    nonce // Explicitly pass the new nonce for the retry proof
                })

                headers.set('DPoP', retryProof)
                console.log('Retrying 401 request with DPoP-Nonce...')

                // Retry attempt
                response = await fetch(input, {
                    ...init,
                    method: method,
                    headers: headers,
                })

                nonce = extractDPoPNonce(response.headers)
            }

            // Store nonce on a successful request so that it can be used
            // for the next request to the same endpoint.
            if (response.ok && nonce) {
                const htu = DPoPUrlNormalizer.normalizeRequestInput(input)
                signer.setNonce(htu, nonce)
            }

            return response
        } catch (error) {
            console.error('DPoP fetch error:', error)
            throw error
        }
    }
}

/**
 * Stores the necessary components required for authenticating requests to protected resources.
 */
class DPoPToken {
    private constructor(
        public readonly accessToken: string,
        public readonly expiresIn: number,
        public readonly type: string,
        public readonly expiresAt: number
    ) {
    }

    public static async fromTokenResponse(response: Response, requestTime: number): Promise<DPoPToken> {
        const json = await response.json()

        if (!json.access_token) {
            throw "Expected access_token in response"
        }

        return new DPoPToken(
            json.access_token,
            json.expires_in,
            json.token_type,
            requestTime + json.expires_in * 1000
        )
    }
}

// Example usage
(async function () {
    'use strict'

    const URL_TOKEN = "http://localhost:8080/token"
    const URL_HIGH_VALUE_RESOURCE = "http://localhost:8080/high-value-resource"
    const URL_LOW_VALUE_RESOURCE = "http://localhost:8080/low-value-resource"
    const URL_CHALLENGE = "http://localhost:8080/challenge"

    const signer = new DPoPSigner()
    await signer.rotateKeyIfNeeded()
    let accessToken: DPoPToken | null = null

    const dpopFetch = createDPoPFetch(fetch, signer, (): string | null => accessToken?.accessToken)

    try {
        console.log('Getting token…')

        const tokenRequestTime = Date.now();
        const tokenResponse = await dpopFetch(URL_TOKEN, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'grant_type=client_credentials',
        })

        if (!tokenResponse.ok) {
            console.error('Token request failed:', tokenResponse.status, await tokenResponse.text())
            return
        }

        accessToken = await DPoPToken.fromTokenResponse(tokenResponse, tokenRequestTime)
        const nonce = extractDPoPNonce(tokenResponse.headers)

        console.log('Access Token:', accessToken)
        console.log('Nonce:', nonce)

        // Use the nonce provided with the token response to skip the challenge of the next request.
        signer.setOneShotNonce(nonce)

        // High Value Resource
        await dpopFetch(URL_HIGH_VALUE_RESOURCE)
        await dpopFetch(URL_HIGH_VALUE_RESOURCE)
        await dpopFetch(URL_HIGH_VALUE_RESOURCE)

        // Low Value Resource
        await dpopFetch(URL_LOW_VALUE_RESOURCE)
        await dpopFetch(URL_LOW_VALUE_RESOURCE)
        await dpopFetch(URL_LOW_VALUE_RESOURCE)

        // Challenge Resource
        await dpopFetch(URL_CHALLENGE) // Should be issued a DPoP-Nonce challenge
        await dpopFetch(URL_CHALLENGE) // Should reuse the DPoP-Nonce from the previous request

    } catch (error) {
        console.error('Request failed:', error)
    }
})()