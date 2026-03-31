import type { JwksKeyStore, JwksRotationTimestampStore } from "./types.ts";

/**
 * In-memory implementation of {@link JwksKeyStore} and {@link JwksRotationTimestampStore}.
 *
 * Suitable for single-process deployments and testing. State is not shared
 * across processes and is lost on restart.
 *
 * Use {@link createInMemoryKeyStore} as a convenience factory.
 */
export class InMemoryKeyStore implements JwksKeyStore, JwksRotationTimestampStore {
  private privateKey?: object;
  private publicKeys: { key: object; exp: number }[] = [];
  private lastRotation: number = 0;

  /**
   * Stores the current signing key pair. The private key replaces the existing one;
   * the public key is appended to the list with a computed expiry based on `ttl`.
   * @param _kid - The key ID (unused by this implementation).
   * @param privateKey - The private key object to store as the active signing key.
   * @param publicKey - The public key object to expose in the JWKS.
   * @param ttl - Time-to-live in seconds for the public key.
   */
  async storeKeyPair(
    _kid: string,
    privateKey: object,
    publicKey: object,
    ttl: number,
  ): Promise<void> {
    this.privateKey = privateKey;
    const exp = Date.now() + ttl * 1000;
    this.publicKeys.push({ key: publicKey, exp });
    return await Promise.resolve();
  }

  /**
   * Retrieves the current private signing key.
   * @returns The private key object, or `undefined` if no key has been stored yet.
   */
  async getPrivateKey(): Promise<object | undefined> {
    return await Promise.resolve(this.privateKey);
  }

  /**
   * Retrieves all public keys that have not yet expired.
   * Expired keys are automatically pruned from the in-memory list on each call.
   * @returns An array of non-expired public key objects.
   */
  async getPublicKeys(): Promise<object[]> {
    const now = Date.now();
    this.publicKeys = this.publicKeys.filter((k) => k.exp > now);
    return await Promise.resolve(this.publicKeys.map((k) => k.key));
  }

  /**
   * Retrieves the Unix timestamp (in milliseconds) of the last key rotation.
   * @returns The timestamp of the last rotation, or `0` if no rotation has occurred.
   */
  async getLastRotationTimestamp(): Promise<number> {
    return await Promise.resolve(this.lastRotation);
  }

  /**
   * Stores the Unix timestamp (in milliseconds) of the most recent key rotation.
   * @param msDate - The timestamp to persist.
   */
  async setLastRotationTimestamp(msDate: number): Promise<void> {
    this.lastRotation = msDate;
    return await Promise.resolve();
  }
}

/**
 * Creates a new {@link InMemoryKeyStore} instance.
 *
 * Convenience factory for use with {@link JoseJwksAuthority} and {@link JwksRotator}.
 *
 * @returns A fresh in-memory key store with no keys stored.
 */
export function createInMemoryKeyStore(): InMemoryKeyStore {
  return new InMemoryKeyStore();
}
