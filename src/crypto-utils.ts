let cachedCrypto: Crypto | null = null;

// Cross-platform crypto getter
export const getCrypto = async (): Promise<Crypto> => {
    if (cachedCrypto) return cachedCrypto;

    if (typeof window !== 'undefined' && window.crypto) {
        cachedCrypto = window.crypto;
        return cachedCrypto;
    }

    if (typeof global !== 'undefined') {
        // Dynamically import only in Node.js
        const { webcrypto } = await import('node:crypto');
        cachedCrypto = webcrypto as unknown as Crypto;
        return cachedCrypto;
    }

    throw new Error('No crypto implementation available');
};

export const getSubtleCrypto = async (): Promise<SubtleCrypto> => {
    const crypto = await getCrypto();
    if (!crypto.subtle) {
        throw new Error('SubtleCrypto not available in this environment');
    }
    return crypto.subtle;
};
