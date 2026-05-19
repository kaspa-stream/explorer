import { bytesToUtf8 } from '@/utils/bytes.js'
import { decodeScript, OP_FALSE, OP_IF, OP_ENDIF } from '@/utils/scriptParser.js'

/**
 * Inscription / envelope detection.
 *
 * Scans the top-level ops for push data items that themselves contain a
 * Kaspa-style inscription envelope:
 *
 *     OP_0 OP_IF <protocol> <…> <JSON> OP_ENDIF
 *
 * When found, attaches in place:
 *   - `op.innerOps`   — decoded inner script
 *   - `op.inscription = { protocol, data }`
 *
 * `innerOps` is only attached when an envelope is actually detected, so the
 * downstream P2SH redeem-script pass can still run on the same push.
 */
export function detectInscriptions(ops) {
  for (const op of ops) {
    const d = op.getPushData()
    if (!d || d.length < 8 || d[d.length - 1] !== OP_ENDIF) continue

    let innerOps
    try {
      innerOps = decodeScript(d)
    } catch {
      continue
    }

    const ifIdx = innerOps.findIndex(
      (o, i) => o.op === OP_FALSE && innerOps[i + 1]?.op === OP_IF,
    )
    if (ifIdx === -1) continue

    const protoOp = innerOps[ifIdx + 2]
    const jsonOp = innerOps.slice(ifIdx + 2).find((o) => {
      const data = o.getPushData()
      return data && data[0] === 0x7b // '{'
    })
    if (!jsonOp) continue

    let data, protocol
    try {
      data = JSON.parse(bytesToUtf8(jsonOp.getPushData()))
    } catch (err) {
      console.warn('Envelope found but content was not valid JSON', err)
      continue
    }
    try {
      protocol = protoOp?.isPush() && protoOp.getPushData()
        ? bytesToUtf8(protoOp.getPushData())
        : 'unknown'
    } catch {
      protocol = 'unknown'
    }

    op.innerOps = innerOps
    op.inscription = { protocol, data }
  }
}
