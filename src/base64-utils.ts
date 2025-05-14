// Cross-platform base64 encoding/decoding utilities
export const base64ToUint8Array = (base64: string): Uint8Array => {
    try {
        if (typeof window !== 'undefined' && window.atob) {
            // Browser environment
            const binaryString = window.atob(base64);
            return Uint8Array.from(binaryString, char => char.charCodeAt(0));
        } else if (typeof Buffer !== 'undefined') {
            // Node.js environment
            return new Uint8Array(Buffer.from(base64, 'base64'));
        }
        throw new Error('No base64 decoder available');
    } catch (err: any) {
        throw new Error(`Invalid base64 string: ${err?.message || 'Unknown error'}`);
    }
};
