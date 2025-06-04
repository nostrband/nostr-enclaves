// Use a promise to prevent race conditions during async initialization
let cryptoPromise: Promise<Crypto> | null = null;

// Cross-platform crypto getter
export const getCrypto = async (): Promise<Crypto> => {
  // If we already have an initialization in progress, return that promise
  if (cryptoPromise) return cryptoPromise;

  // Create a new promise for the initialization
  cryptoPromise = (async (): Promise<Crypto> => {
    // Check browser environment
    if (typeof window !== "undefined" && window.crypto) {
      return window.crypto;
    }

    // Check Node.js environment
    if (typeof global !== "undefined") {
      // Dynamically import only in Node.js
      const { webcrypto } = await import("node:crypto");
      return webcrypto as unknown as Crypto;
    }

    throw new Error("No crypto implementation available");
  })();

  return cryptoPromise;
};

export const getSubtleCrypto = async (): Promise<SubtleCrypto> => {
  const crypto = await getCrypto();
  if (!crypto.subtle) {
    throw new Error("SubtleCrypto not available in this environment");
  }
  return crypto.subtle;
};
