import { bytesToHex } from '@/utils/bytes.js'
import {
  OP_1,
  OP_16,
  OP_BLAKE2B,
  OP_CAT,
  OP_CHECKLOCKTIMEVERIFY,
  OP_CHECKMULTISIG,
  OP_CHECKMULTISIG_ECDSA,
  OP_CHECKSEQUENCEVERIFY,
  OP_CHECKSIG,
  OP_CHECKSIG_ECDSA,
  OP_DROP,
  OP_DUP,
  OP_ELSE,
  OP_ENDIF,
  OP_EQUAL,
  OP_EQUALVERIFY,
  OP_FALSE,
  OP_IF,
  OP_NOTIF,
  OP_PICK,
  OP_PUSH_1,
  OP_PUSH_32,
  OP_PUSH_33,
  OP_ROT,
  OP_SHA256,
  OP_SWAP,
  OP_ZK_PRECOMPILE,
} from '@/utils/scriptParser.js'

/**
 * Opcode fingerprinting & higher-level pattern recognition.
 *
 * - {@link COVENANT_OPCODES} — fingerprint set; presence in a redeem script
 *   flips the script's `covenant` flag.
 * - {@link detectScriptPattern} — recognises common templated redeem-script
 *   shapes and returns a structured summary.
 * - {@link describePattern} — pure transform from pattern result to a
 *   view-model the UI can render with a single template loop.
 */

// All opcodes gated by `covenants_enabled` (Toccata hardfork) plus the
// always-active introspection opcodes. Sourced from rusty-kaspa
// crypto/txscript/src/opcodes/mod.rs.
export const COVENANT_OPCODES = new Set([
  // Splice
  0x7e, 0x7f,
  // Bitwise
  0x83, 0x84, 0x85, 0x86,
  // Re-enabled arithmetic
  0x95, 0x96, 0x97,
  // ZK precompile / keyed Blake2b
  0xa6, 0xa7,
  // Tx-level introspection
  0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
  // Input-level introspection
  0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
  // UTXO + output-level introspection
  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
  // Auth / covenant context
  0xcb, 0xcc, 0xcd, 0xce, 0xcf,
  0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
  // Output covenant context + stack sigverify + Blake3 (Toccata)
  0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
])

// --- shared helpers ----------------------------------------------------------

const isAllZeroBytes = (v) => !!v && v.length > 0 && v.every((b) => b === 0)

/** Integer value of OP_0..OP_16, else `null`. */
function readSmallInt(op) {
  if (op === OP_FALSE) return 0
  if (op >= OP_1 && op <= OP_16) return op - (OP_1 - 1)
  return null
}

/** Decode a minimal-encoded script-num (signed little-endian, ≤ 5 bytes). */
function readScriptNum(bytes) {
  if (!bytes || bytes.length === 0) return 0
  if (bytes.length > 5) return null
  let n = 0n
  for (let i = 0; i < bytes.length; i++) n |= BigInt(bytes[i]) << BigInt(8 * i)
  const signBit = 1n << BigInt(8 * bytes.length - 1)
  if (n & signBit) n = -(n & ~signBit)
  return n <= BigInt(Number.MAX_SAFE_INTEGER) && n >= BigInt(Number.MIN_SAFE_INTEGER)
    ? Number(n)
    : n
}

/** Numeric value pushed as OP_<N> small-int or as a direct push (≤ 5 bytes). */
function readPushedNumber(op) {
  const small = readSmallInt(op.op)
  if (small !== null) return small
  if (op.value && op.value.length > 0 && op.value.length <= 5) return readScriptNum(op.value)
  return null
}

/** Read a `<num> (OP_CLTV|OP_CSV) OP_DROP` triple at body[i]; returns {value, mode, next} or null. */
function readTimelockTriple(body, i) {
  if (body.length - i < 3) return null
  const value = readPushedNumber(body[i])
  if (value === null) return null
  const lockOp = body[i + 1]?.op
  if (lockOp !== OP_CHECKLOCKTIMEVERIFY && lockOp !== OP_CHECKSEQUENCEVERIFY) return null
  if (body[i + 2]?.op !== OP_DROP) return null
  return { value, mode: lockOp === OP_CHECKLOCKTIMEVERIFY ? 'cltv' : 'csv', next: i + 3 }
}

const isPush32 = (op) => op?.op === OP_PUSH_32 && op.value?.length === 32

// --- pattern entry point -----------------------------------------------------

/**
 * @returns {{branches: Array<{selector?: number, kind: object}>, templateTag: string|null}|null}
 */
export function detectScriptPattern(ops) {
  if (!Array.isArray(ops) || ops.length < 2) return null

  const multi = detectMultiBranchPattern(ops)
  if (multi) return multi

  const kind = classifyBody(ops)
  if (kind.type !== 'unknown') return { branches: [{ kind }], templateTag: null }

  return null
}

// --- multi-branch selector ---------------------------------------------------

function detectMultiBranchPattern(ops) {
  const branches = []
  let i = 0
  let elseDepth = 0

  while (matchSelectorPrefix(ops, i)) {
    const selector = ops[i + 1].value[0]
    const bodyStart = i + 5
    const elseIdx = findCloseAtDepth(ops, bodyStart, OP_ELSE)
    if (elseIdx === -1) return null
    branches.push({ selector, body: ops.slice(bodyStart, elseIdx) })
    i = elseIdx + 1
    elseDepth++
  }

  if (matchFinalBranchPrefix(ops, i)) {
    const selector = ops[i].value[0]
    const bodyStart = i + 3
    const endifIdx = findCloseAtDepth(ops, bodyStart, OP_ENDIF)
    if (endifIdx === -1) return null
    branches.push({ selector, body: ops.slice(bodyStart, endifIdx) })
    i = endifIdx
  }

  if (branches.length === 0) return null

  let endifs = 0
  while (i < ops.length && ops[i].op === OP_ENDIF) {
    endifs++
    i++
  }
  if (endifs !== elseDepth) return null

  let templateTag = null
  if (i + 1 < ops.length && isPush32(ops[i]) && ops[i + 1].op === OP_DROP) {
    templateTag = bytesToHex(ops[i].value)
    i += 2
  }
  if (i !== ops.length) return null

  return {
    branches: branches.map((b) => ({ selector: b.selector, kind: classifyBody(b.body) })),
    templateTag,
  }
}

function matchSelectorPrefix(ops, i) {
  return (
    i + 4 < ops.length &&
    ops[i].op === OP_DUP &&
    ops[i + 1].op === OP_PUSH_1 &&
    ops[i + 1].value?.length === 1 &&
    ops[i + 2].op === OP_EQUAL &&
    ops[i + 3].op === OP_IF &&
    ops[i + 4].op === OP_DROP
  )
}

function matchFinalBranchPrefix(ops, i) {
  return (
    i + 2 < ops.length &&
    ops[i].op === OP_PUSH_1 &&
    ops[i].value?.length === 1 &&
    ops[i + 1].op === OP_EQUALVERIFY &&
    ops[i + 2].op === OP_DROP
  )
}

function findCloseAtDepth(ops, start, closer) {
  let nest = 1
  for (let j = start; j < ops.length; j++) {
    const op = ops[j].op
    if (op === OP_IF || op === OP_NOTIF) nest++
    else if (op === OP_ENDIF) {
      nest--
      if (nest === 0) return closer === OP_ENDIF ? j : -1
    } else if (op === closer && nest === 1) {
      return j
    }
  }
  return -1
}

// --- body classifiers --------------------------------------------------------

const MATCHERS = [matchHtlc, matchTimelocked, matchMerkleProof, matchMultisig, matchZkPrecompile, matchP2pk]

/** Try every body matcher in order; returns `{type: 'unknown'}` if none match. */
function classifyBody(body) {
  for (const m of MATCHERS) {
    const k = m(body)
    if (k) return k
  }
  return { type: 'unknown' }
}

// PUSH_32 <pk> OP_CHECKSIG  |  PUSH_33 <pk> OP_CHECKSIG_ECDSA
function matchP2pk(body) {
  if (body.length !== 2) return null
  const head = body[0]
  if (isPush32(head) && body[1].op === OP_CHECKSIG) {
    return p2pkResult('schnorr', head.value)
  }
  if (head.op === OP_PUSH_33 && head.value?.length === 33 && body[1].op === OP_CHECKSIG_ECDSA) {
    return p2pkResult('ecdsa', head.value)
  }
  return null
}

function p2pkResult(scheme, keyBytes) {
  return { type: 'p2pk', scheme, pubkey: bytesToHex(keyBytes), disabled: isAllZeroBytes(keyBytes) }
}

// OP_<M> <key1>…<keyN> OP_<N> OP_CHECKMULTISIG[_ECDSA]
function matchMultisig(body) {
  if (body.length < 4) return null
  const last = body[body.length - 1].op
  const isEcdsa = last === OP_CHECKMULTISIG_ECDSA
  if (!isEcdsa && last !== OP_CHECKMULTISIG) return null

  const m = readSmallInt(body[0].op)
  const n = readSmallInt(body[body.length - 2].op)
  if (m === null || n === null || m < 1 || n < m) return null

  const expectedOp = isEcdsa ? OP_PUSH_33 : OP_PUSH_32
  const expectedLen = isEcdsa ? 33 : 32
  const pubkeys = []
  for (let i = 1; i < body.length - 2; i++) {
    const k = body[i]
    if (k.op !== expectedOp || k.value?.length !== expectedLen) return null
    pubkeys.push(bytesToHex(k.value))
  }
  if (pubkeys.length !== n) return null

  return { type: 'multisig', scheme: isEcdsa ? 'ecdsa' : 'schnorr', m, n, pubkeys }
}

// <num> (OP_CLTV|OP_CSV) OP_DROP <inner>
function matchTimelocked(body) {
  if (body.length < 4) return null
  const lock = readTimelockTriple(body, 0)
  if (!lock) return null
  return {
    type: 'timelocked',
    mode: lock.mode,
    value: lock.value,
    inner: classifyBody(body.slice(lock.next)),
  }
}

// OP_IF (OP_SHA256|OP_BLAKE2B) PUSH_32 <hash> OP_EQUALVERIFY <claim> OP_CHECKSIG
// OP_ELSE <num> (OP_CLTV|OP_CSV) OP_DROP <refund> OP_CHECKSIG OP_ENDIF
function matchHtlc(body) {
  if (
    body.length < 13 ||
    body[0].op !== OP_IF ||
    (body[1].op !== OP_SHA256 && body[1].op !== OP_BLAKE2B) ||
    !isPush32(body[2]) ||
    body[3].op !== OP_EQUALVERIFY ||
    !isPush32(body[4]) ||
    body[5].op !== OP_CHECKSIG ||
    body[6].op !== OP_ELSE
  ) {
    return null
  }

  const lock = readTimelockTriple(body, 7)
  if (!lock) return null
  const i = lock.next
  if (
    !isPush32(body[i]) ||
    body[i + 1]?.op !== OP_CHECKSIG ||
    body[i + 2]?.op !== OP_ENDIF ||
    i + 3 !== body.length
  ) {
    return null
  }

  return {
    type: 'htlc',
    hashAlgo: body[1].op === OP_SHA256 ? 'sha256' : 'blake2b',
    hash: bytesToHex(body[2].value),
    claimKey: bytesToHex(body[4].value),
    refundKey: bytesToHex(body[i].value),
    mode: lock.mode,
    timelock: lock.value,
    disabled: isAllZeroBytes(body[4].value) || isAllZeroBytes(body[i].value),
  }
}

// Merkle-set membership:
//   <PUSH_1 D> OP_PICK
//   (OP_BLAKE2B OP_ROT OP_ROT OP_IF OP_SWAP OP_ENDIF OP_CAT){N}
//   OP_BLAKE2B PUSH_32 <root> OP_EQUALVERIFY OP_DROP PUSH_32 <pubkey> OP_CHECKSIG
function matchMerkleProof(body) {
  if (
    body.length < 11 ||
    body[0].op !== OP_PUSH_1 ||
    body[0].value?.length !== 1 ||
    body[1].op !== OP_PICK
  ) {
    return null
  }

  let k = 2
  let depth = 0
  while (
    k + 6 < body.length &&
    body[k].op === OP_BLAKE2B &&
    body[k + 1].op === OP_ROT &&
    body[k + 2].op === OP_ROT &&
    body[k + 3].op === OP_IF &&
    body[k + 4].op === OP_SWAP &&
    body[k + 5].op === OP_ENDIF &&
    body[k + 6].op === OP_CAT
  ) {
    depth++
    k += 7
  }

  if (
    depth === 0 ||
    body[k]?.op !== OP_BLAKE2B ||
    !isPush32(body[k + 1]) ||
    body[k + 2]?.op !== OP_EQUALVERIFY ||
    body[k + 3]?.op !== OP_DROP ||
    !isPush32(body[k + 4]) ||
    body[k + 5]?.op !== OP_CHECKSIG ||
    k + 6 !== body.length
  ) {
    return null
  }

  return {
    type: 'merkleProof',
    depth,
    stackDepth: body[0].value[0],
    root: bytesToHex(body[k + 1].value),
    pubkey: bytesToHex(body[k + 4].value),
    disabled: isAllZeroBytes(body[k + 4].value),
  }
}

// Anything using OP_ZK_PRECOMPILE; the push immediately preceding the opcode
// is the verification tag (rusty-kaspa pops it off the stack).
function matchZkPrecompile(body) {
  const idx = body.findIndex((o) => o.op === OP_ZK_PRECOMPILE)
  if (idx === -1) return null
  const tagData = idx > 0 ? body[idx - 1].getPushData?.() : null
  return { type: 'zkPrecompile', tag: tagData ? bytesToHex(tagData) : null }
}

// --- view-model transform ---------------------------------------------------

const SCHEME_LABEL = { schnorr: 'Schnorr', ecdsa: 'ECDSA' }
const LOCK_LABEL = { cltv: 'absolute (CLTV)', csv: 'relative (CSV)' }
const HASH_LABEL = { sha256: 'SHA-256', blake2b: 'BLAKE2B' }

/**
 * Reduce a {@link detectScriptPattern} result to a pure view-model:
 *
 *   {
 *     headline: string,
 *     templateTag: string | null,
 *     branches: [
 *       {
 *         label: string | null,   // e.g. "Branch 1" or null for single-script
 *         chips: [{ text, color, variant?, helpKey? }],
 *         rows:  [{ label, value, helpKey? }],
 *         nested?: { chips, rows, nested? }   // for timelocked.inner
 *       }
 *     ]
 *   }
 *
 * `helpKey` references the HELP map in the consuming component so tooltip
 * copy stays a UI concern.
 */
export function describePattern(pattern) {
  if (!pattern) return null
  const multi = pattern.branches.length > 1 || pattern.branches[0]?.selector !== undefined
  return {
    headline: multi
      ? `Detected pattern: ${pattern.branches.length}-branch selector script`
      : 'Detected pattern: single-template script',
    multi,
    templateTag: pattern.templateTag,
    branches: pattern.branches.map((b) => describeBranch(b)),
  }
}

function describeBranch(branch) {
  const view = describeKind(branch.kind)
  view.label = branch.selector !== undefined ? `Branch ${branch.selector}` : null
  return view
}

function describeKind(kind = { type: 'unknown' }) {
  switch (kind.type) {
    case 'p2pk':
      return {
        chips: [
          { text: `P2PK (${SCHEME_LABEL[kind.scheme] || kind.scheme})`, color: 'secondary', helpKey: 'p2pk' },
          ...disabledChip(kind),
        ],
        rows: [{ label: 'Pubkey', value: kind.pubkey }],
      }
    case 'multisig':
      return {
        chips: [
          {
            text: `${kind.m}-of-${kind.n} multisig (${SCHEME_LABEL[kind.scheme] || kind.scheme})`,
            color: 'secondary',
            helpKey: 'multisig',
          },
        ],
        rows: kind.pubkeys.map((k, i) => ({ label: `Pubkey ${i + 1} / ${kind.n}`, value: k })),
      }
    case 'timelocked':
      return {
        chips: [
          {
            text: `Timelocked — ${LOCK_LABEL[kind.mode]} ≥ ${kind.value}`,
            color: 'info',
            helpKey: 'timelocked',
          },
        ],
        rows: [],
        nested: describeKind(kind.inner),
      }
    case 'htlc':
      return {
        chips: [{ text: 'HTLC (hash-or-timelock)', color: 'info', helpKey: 'htlc' }, ...disabledChip(kind)],
        rows: [
          { label: `${HASH_LABEL[kind.hashAlgo]} preimage hash`, value: kind.hash },
          { label: 'Claim pubkey', value: kind.claimKey },
          { label: 'Refund pubkey', value: kind.refundKey },
          {
            label: 'Refund timelock',
            value: `${LOCK_LABEL[kind.mode]} ≥ ${kind.timelock}`,
            mono: false,
          },
        ],
      }
    case 'merkleProof':
      return {
        chips: [
          {
            text: `Merkle-set membership (depth ${kind.depth}, up to ${2 ** kind.depth} keys)`,
            color: 'info',
            helpKey: 'merkleProof',
          },
          ...disabledChip(kind),
        ],
        rows: [
          { label: 'Authority pubkey', value: kind.pubkey, helpKey: 'authorityKey' },
          { label: 'Authorized set Merkle root', value: kind.root, helpKey: 'merkleRoot' },
        ],
      }
    case 'zkPrecompile':
      return {
        chips: [{ text: 'ZK precompile', color: 'info', helpKey: 'zkPrecompile' }],
        rows: kind.tag ? [{ label: 'Verification tag', value: kind.tag }] : [],
      }
    default:
      return {
        chips: [{ text: 'Unrecognised body', color: 'grey', variant: 'outlined' }],
        rows: [],
      }
  }
}

function disabledChip(kind) {
  if (!kind.disabled) return []
  return [{ text: 'disabled (null pubkey)', color: 'grey', variant: 'outlined', helpKey: 'disabledKey' }]
}
