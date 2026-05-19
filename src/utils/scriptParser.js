import { hexToBytes } from '@/utils/bytes.js'

/**
 * Low-level Kaspa script byte-stream parser.
 *
 * Produces a flat array of {@link ScriptOp} from a hex string or byte array.
 * Higher-level concerns (P2SH redeem-script extraction, inscription envelope
 * detection, pattern recognition) live in sibling modules and operate on the
 * decoded ops produced here.
 */

// --- opcode constants used by this parser and the pattern detector ----------

export const OP_FALSE = 0x00
export const OP_PUSH_1 = 0x01
export const OP_PUSH_DATA_MAX = 0x4b
export const OP_PUSHDATA1 = 0x4c
export const OP_PUSHDATA2 = 0x4d
export const OP_PUSHDATA4 = 0x4e
export const OP_PUSH_32 = 0x20
export const OP_PUSH_33 = 0x21
export const OP_1NEGATE = 0x4f
export const OP_1 = 0x51
export const OP_16 = 0x60
export const OP_LAST_PUSH = OP_16
export const OP_IF = 0x63
export const OP_NOTIF = 0x64
export const OP_ELSE = 0x67
export const OP_ENDIF = 0x68
export const OP_DROP = 0x75
export const OP_DUP = 0x76
export const OP_PICK = 0x79
export const OP_ROT = 0x7b
export const OP_SWAP = 0x7c
export const OP_CAT = 0x7e
export const OP_EQUAL = 0x87
export const OP_EQUALVERIFY = 0x88
export const OP_ZK_PRECOMPILE = 0xa6
export const OP_SHA256 = 0xa8
export const OP_CHECKMULTISIG_ECDSA = 0xa9
export const OP_BLAKE2B = 0xaa
export const OP_CHECKSIG_ECDSA = 0xab
export const OP_CHECKSIG = 0xac
export const OP_CHECKMULTISIG = 0xae
export const OP_CHECKLOCKTIMEVERIFY = 0xb0
export const OP_CHECKSEQUENCEVERIFY = 0xb1

// length-prefix width (in bytes) per PUSHDATA opcode
const PUSHDATA_PREFIX_SIZE = {
  [OP_PUSHDATA1]: 1,
  [OP_PUSHDATA2]: 2,
  [OP_PUSHDATA4]: 4,
}

export class ScriptError extends Error {
  static UnexpectedEof = new ScriptError('Unexpected end of script')
}

export class ScriptOp {
  constructor(op, value = null) {
    this.op = op
    this.value = value
  }

  /** True for any opcode in the push range (0x00–OP_16). */
  isPush() {
    return this.op <= OP_LAST_PUSH
  }

  /** Returns the pushed bytes for direct/PUSHDATA pushes, else `null`. */
  getPushData() {
    return this.value
  }
}

/**
 * Decode a raw script (hex string, Uint8Array, or array-like) into ops.
 * Throws {@link ScriptError.UnexpectedEof} on truncated push data.
 */
export function decodeScript(script) {
  const bytes = toBytes(script)
  const ops = []
  let i = 0
  while (i < bytes.length) {
    const op = bytes[i++]
    let value = null

    if (op >= OP_PUSH_1 && op <= OP_PUSH_DATA_MAX) {
      value = read(bytes, i, op)
      i += op
    } else if (PUSHDATA_PREFIX_SIZE[op]) {
      const prefix = PUSHDATA_PREFIX_SIZE[op]
      const len = readUintLE(bytes, i, prefix)
      i += prefix
      value = read(bytes, i, len)
      i += len
    }

    ops.push(new ScriptOp(op, value))
  }
  return ops
}

function toBytes(script) {
  if (typeof script === 'string') return script.length === 0 ? new Uint8Array() : hexToBytes(script)
  if (script instanceof Uint8Array) return script
  return new Uint8Array(script)
}

function read(bytes, i, n) {
  if (i + n > bytes.length) throw ScriptError.UnexpectedEof
  return bytes.slice(i, i + n)
}

function readUintLE(bytes, i, width) {
  if (i + width > bytes.length) throw ScriptError.UnexpectedEof
  let n = 0
  for (let k = 0; k < width; k++) n |= bytes[i + k] << (8 * k)
  return n >>> 0
}
