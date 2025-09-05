/**
 * Crypto utilities (placeholder - functionality integrated into main analyzer)
 * 
 * Note: AES decryption is handled by the Web Crypto API in firmware-analyzer.js
 * This file could be extended for additional cryptographic operations if needed.
 */

// Web Crypto API AES-ECB polyfill if needed
if (!crypto.subtle.encrypt || !crypto.subtle.decrypt) {
    console.warn('Web Crypto API not fully supported. Some features may not work.');
}

/**
 * Convert string to Uint8Array
 */
function stringToUint8Array(str) {
    const arr = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        arr[i] = str.charCodeAt(i);
    }
    return arr;
}

/**
 * Convert Uint8Array to string
 */
function uint8ArrayToString(arr) {
    return String.fromCharCode.apply(null, arr);
}

/**
 * Pad Uint8Array to specified length
 */
function padUint8Array(arr, length) {
    if (arr.length >= length) {
        return arr.slice(0, length);
    }
    
    const padded = new Uint8Array(length);
    padded.set(arr);
    // Remaining bytes are already 0
    return padded;
}