import { describe, it, expect, beforeAll } from 'vitest';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

let Keychain;
beforeAll(async () => {
    ({ Keychain } = await import('./keychain.js'));
});

const MASTER = 'correct-horse-battery';

describe('Keychain', () => {
    it('saves a password and reads it back', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('github.com', 'MyP@ss123');
        expect(await kc.get('github.com')).toBe('MyP@ss123');
    });

    it('returns null for a domain that was never saved', async () => {
        const kc = await Keychain.init(MASTER);
        expect(await kc.get('unknown.com')).toBeNull();
    });

    it('overwrites an existing entry when set again', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('site.com', 'old');
        await kc.set('site.com', 'new');
        expect(await kc.get('site.com')).toBe('new');
    });

    it('removes an entry (true) and reports a missing one (false)', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('site.com', 'pw');
        expect(await kc.remove('site.com')).toBe(true);
        expect(await kc.get('site.com')).toBeNull();
        expect(await kc.remove('site.com')).toBe(false);
    });

    it('survives dump() then load() with the right master password', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('strathmore.edu', 'Str@th2026');
        const [repr, hash] = await kc.dump();

        const loaded = await Keychain.load(MASTER, repr, hash);
        expect(await loaded.get('strathmore.edu')).toBe('Str@th2026');
    });

    it('rejects a wrong master password', async () => {
        const kc = await Keychain.init(MASTER);
        const [repr, hash] = await kc.dump();
        await expect(Keychain.load('wrong-password', repr, hash))
            .rejects.toThrow('Incorrect master password.');
    });

    it('detects tampering with the saved data (checksum mismatch)', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('site.com', 'pw');
        const [repr, hash] = await kc.dump();
        const tampered = repr.replace('"kvs"', '"kvs "');
        await expect(Keychain.load(MASTER, tampered, hash))
            .rejects.toThrow('Integrity check failed.');
    });

    it('does not store the domain name or password in plaintext', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('github.com', 'SuperSecret99');
        const [repr] = await kc.dump();
        expect(repr).not.toContain('github.com');
        expect(repr).not.toContain('SuperSecret99');
    });

    it('pads passwords so ciphertext length does not reveal password length', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('short.com', 'a');
        await kc.set('long.com', 'a-much-longer-password-1234567890');
        const lengths = Object.values(kc.data.kvs).map(r => r.ciphertext.length);
        expect(lengths[0]).toBe(lengths[1]);
    });

    it('uses a fresh random IV, so the same password encrypts differently each time', async () => {
        const kc = await Keychain.init(MASTER);
        await kc.set('site.com', 'same-password');
        const first = JSON.stringify(Object.values(kc.data.kvs)[0]);
        await kc.set('site.com', 'same-password');
        const second = JSON.stringify(Object.values(kc.data.kvs)[0]);
        expect(first).not.toBe(second);
    });
});