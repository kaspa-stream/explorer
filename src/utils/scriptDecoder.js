import { decodeScript, OP_LAST_PUSH, ScriptError, ScriptOp } from '@/utils/scriptParser.js'
import { detectInscriptions } from '@/utils/scriptEnvelope.js'
import { COVENANT_OPCODES, describePattern, detectScriptPattern } from '@/utils/scriptPatterns.js'

/**
 * Master switch for higher-level pattern recognition. Flip to `false` to skip
 * the structural pattern detector and fall back to plain opcode display.
 * Inscription envelope detection and the covenant fingerprint are unaffected.
 */
export const PATTERN_DETECTION_ENABLED = true

// Public re-exports — keep existing consumer imports stable.
export { decodeScript, describePattern, ScriptError, ScriptOp }

/**
 * Decode a Kaspa signature script and enrich it with higher-level structure:
 *
 *   - Inscription envelopes (`op.innerOps` + `op.inscription`).
 *   - P2SH redeem-script expansion on the last push-data item
 *     (`op.innerOps`).
 *   - `op.covenant = true` if any opcode in the redeem script is a
 *     covenants_enabled-gated opcode.
 *   - `op.pattern` with branch + template-tag info when
 *     {@link PATTERN_DETECTION_ENABLED} is true and the redeem script matches
 *     a known template (see scriptPatterns.js).
 *
 * Returns `{ ops }` on success or `null` if the top-level script can't be
 * parsed at all.
 */
export function decodeScriptAndEnvelope(scriptHex) {
  let ops
  try {
    ops = decodeScript(scriptHex)
  } catch {
    return null
  }

  detectInscriptions(ops)
  enrichRedeemScript(ops)

  return { ops }
}

// The last pushdata in a P2SH signature script is the redeem script. Decode
// it once, mark covenant usage, and (optionally) run pattern detection.
//
// P2SH spends always carry at least one signature push *before* the redeem
// script, so a single-op top-level script (e.g. a bare Schnorr signature)
// is treated as a plain push and left alone.
function enrichRedeemScript(ops) {
  if (ops.length < 2) return
  const lastPushOp = findLastPushData(ops)
  if (!lastPushOp || lastPushOp.innerOps) return

  const data = lastPushOp.getPushData()
  if (!data || data.length === 0) return

  let innerOps
  try {
    innerOps = decodeScript(data)
  } catch {
    return
  }

  // Heuristic: at least one non-push opcode → worth treating as a script.
  if (!innerOps.some((o) => o.op > OP_LAST_PUSH)) return

  lastPushOp.innerOps = innerOps
  if (innerOps.some((o) => COVENANT_OPCODES.has(o.op))) lastPushOp.covenant = true

  if (PATTERN_DETECTION_ENABLED) {
    const pattern = detectScriptPattern(innerOps)
    if (pattern) lastPushOp.pattern = pattern
  }
}

function findLastPushData(ops) {
  for (let i = ops.length - 1; i >= 0; i--) {
    if (ops[i].getPushData() !== null) return ops[i]
  }
  return null
}
