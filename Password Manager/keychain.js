const stringToBuffer = str => new TextEncoder().encode(str);
const bufferToString = buf => new TextDecoder().decode(buf);
const encodeBuffer = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const decodeBuffer = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));
const getRandomBytes = len => globalThis.crypto.getRandomValues(new Uint8Array(len));
const subtle = globalThis.crypto.subtle;

const PBKDF2_ITERATIONS = 100000, MAX_PASSWORD_LENGTH = 64;
const SALT_LENGTH = 16, IV_LENGTH = 12, RECORD_LENGTH = MAX_PASSWORD_LENGTH + 1;
const HMAC_SUBKEY_LABEL = "hmac-domain-key", AES_SUBKEY_LABEL = "aes-gcm-value-key";
const PASSWORD_CHECK_PLAINTEXT = "password-manager-verification-sentinel";

export class Keychain {
    constructor(hmacKey, aesKey, salt, kvs, passwordCheck) {
        this.data = { kvs: kvs || {}, salt: salt, passwordCheck: passwordCheck };
        this.secrets = { hmacKey: hmacKey, aesKey: aesKey };
    }

    static async deriveKeys(password, saltBuffer) {
        const rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey", "deriveBits"]);
        const masterKey = await subtle.deriveKey({ name: "PBKDF2", salt: saltBuffer, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, rawKey, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
        const hmacKeyBits = await subtle.sign("HMAC", masterKey, stringToBuffer(HMAC_SUBKEY_LABEL));
        const aesKeyBits = await subtle.sign("HMAC", masterKey, stringToBuffer(AES_SUBKEY_LABEL));
        const hmacKey = await subtle.importKey("raw", hmacKeyBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
        const aesKey = await subtle.importKey("raw", aesKeyBits.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
        return { hmacKey, aesKey };
    }

    async domainTag(name) { return encodeBuffer(await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name))); }

    static async init(password) {
        const salt = getRandomBytes(SALT_LENGTH);
        const { hmacKey, aesKey } = await Keychain.deriveKeys(password, salt);
        const iv = getRandomBytes(IV_LENGTH);
        const ctBuffer = await subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, stringToBuffer(PASSWORD_CHECK_PLAINTEXT));
        return new Keychain(hmacKey, aesKey, encodeBuffer(salt), {}, { iv: encodeBuffer(iv), ciphertext: encodeBuffer(ctBuffer) });
    }

    static async load(password, repr, trustedDataCheck) {
        if (trustedDataCheck) {
            const computed = await subtle.digest("SHA-256", stringToBuffer(repr));
            if (encodeBuffer(computed) !== trustedDataCheck) throw new Error("Integrity check failed.");
        }
        const parsed = JSON.parse(repr);
        const { hmacKey, aesKey } = await Keychain.deriveKeys(password, decodeBuffer(parsed.salt));
        try {
            const pc = parsed.passwordCheck;
            const plain = await subtle.decrypt({ name: "AES-GCM", iv: decodeBuffer(pc.iv) }, aesKey, decodeBuffer(pc.ciphertext));
            if (bufferToString(plain) !== PASSWORD_CHECK_PLAINTEXT) throw new Error("Mismatch");
        } catch (e) { throw new Error("Incorrect master password."); }
        return new Keychain(hmacKey, aesKey, parsed.salt, parsed.kvs, parsed.passwordCheck);
    }

    async dump() {
        const repr = JSON.stringify(this.data);
        return [repr, encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)))];
    }

    async get(name) {
        const tag = await this.domainTag(name);
        if (!this.data.kvs[tag]) return null;
        const rec = this.data.kvs[tag];
        const plainBuffer = await subtle.decrypt({ name: "AES-GCM", iv: decodeBuffer(rec.iv), additionalData: stringToBuffer(tag) }, this.secrets.aesKey, decodeBuffer(rec.ciphertext));
        const bytes = new Uint8Array(plainBuffer);
        return bufferToString(bytes.slice(1, 1 + bytes[0]));
    }

    async set(name, value) {
        const tag = await this.domainTag(name);
        const valueBytes = stringToBuffer(value);
        const out = new Uint8Array(RECORD_LENGTH);
        out[0] = valueBytes.length; out.set(valueBytes, 1);

        const iv = getRandomBytes(IV_LENGTH);
        const ctBuffer = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: stringToBuffer(tag) }, this.secrets.aesKey, out);
        this.data.kvs[tag] = { iv: encodeBuffer(iv), ciphertext: encodeBuffer(ctBuffer) };
    }

    async remove(name) {
        const tag = await this.domainTag(name);
        if (!this.data.kvs[tag]) return false;
        delete this.data.kvs[tag]; return true;
    }
}