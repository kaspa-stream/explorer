export const hexToBytes = hex => Uint8Array.from(hex.match(/../g), b => parseInt(b, 16))
export const bytesToHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
export const bytesToUtf8 = bytes => new TextDecoder().decode(bytes)
export const base64ToBytes = str => Uint8Array.from(atob(str), c => c.charCodeAt(0))
