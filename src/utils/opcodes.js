/**
 * Kaspa Script opcodes, sourced from rusty-kaspa/crypto/txscript/src/opcodes/mod.rs
 */
export const OP_MAP = {
    // Constants
    0x00: 'OP_FALSE',
    // 0x01-0x4b: push data (handled dynamically in getOpDecode)
    // 0x4c-0x4e: OP_PUSHDATA1/2/4 (handled dynamically)
    0x4f: 'OP_1NEGATE',
    0x50: 'OP_RESERVED',
    0x51: 'OP_1',
    0x52: 'OP_2',
    0x53: 'OP_3',
    0x54: 'OP_4',
    0x55: 'OP_5',
    0x56: 'OP_6',
    0x57: 'OP_7',
    0x58: 'OP_8',
    0x59: 'OP_9',
    0x5a: 'OP_10',
    0x5b: 'OP_11',
    0x5c: 'OP_12',
    0x5d: 'OP_13',
    0x5e: 'OP_14',
    0x5f: 'OP_15',
    0x60: 'OP_16',

    // Flow Control
    0x61: 'OP_NOP',
    0x62: 'OP_VER',
    0x63: 'OP_IF',
    0x64: 'OP_NOTIF',
    0x65: 'OP_VERIF',
    0x66: 'OP_VERNOTIF',
    0x67: 'OP_ELSE',
    0x68: 'OP_ENDIF',
    0x69: 'OP_VERIFY',
    0x6a: 'OP_RETURN',

    // Stack Manipulation
    0x6b: 'OP_TOALTSTACK',
    0x6c: 'OP_FROMALTSTACK',
    0x6d: 'OP_2DROP',
    0x6e: 'OP_2DUP',
    0x6f: 'OP_3DUP',
    0x70: 'OP_2OVER',
    0x71: 'OP_2ROT',
    0x72: 'OP_2SWAP',
    0x73: 'OP_IFDUP',
    0x74: 'OP_DEPTH',
    0x75: 'OP_DROP',
    0x76: 'OP_DUP',
    0x77: 'OP_NIP',
    0x78: 'OP_OVER',
    0x79: 'OP_PICK',
    0x7a: 'OP_ROLL',
    0x7b: 'OP_ROT',
    0x7c: 'OP_SWAP',
    0x7d: 'OP_TUCK',

    // Splice (disabled in Kaspa, except OP_SIZE)
    0x7e: 'OP_CAT',
    0x7f: 'OP_SUBSTR',
    0x80: 'OP_LEFT',
    0x81: 'OP_RIGHT',
    0x82: 'OP_SIZE',

    // Bitwise (disabled in Kaspa)
    0x83: 'OP_INVERT',
    0x84: 'OP_AND',
    0x85: 'OP_OR',
    0x86: 'OP_XOR',

    // Logic / Comparison
    0x87: 'OP_EQUAL',
    0x88: 'OP_EQUALVERIFY',
    0x89: 'OP_RESERVED1',
    0x8a: 'OP_RESERVED2',

    // Arithmetic
    0x8b: 'OP_1ADD',
    0x8c: 'OP_1SUB',
    0x8d: 'OP_2MUL',
    0x8e: 'OP_2DIV',
    0x8f: 'OP_NEGATE',
    0x90: 'OP_ABS',
    0x91: 'OP_NOT',
    0x92: 'OP_0NOTEQUAL',
    0x93: 'OP_ADD',
    0x94: 'OP_SUB',
    0x95: 'OP_MUL',
    0x96: 'OP_DIV',
    0x97: 'OP_MOD',
    0x98: 'OP_LSHIFT',
    0x99: 'OP_RSHIFT',
    0x9a: 'OP_BOOLAND',
    0x9b: 'OP_BOOLOR',
    0x9c: 'OP_NUMEQUAL',
    0x9d: 'OP_NUMEQUALVERIFY',
    0x9e: 'OP_NUMNOTEQUAL',
    0x9f: 'OP_LESSTHAN',
    0xa0: 'OP_GREATERTHAN',
    0xa1: 'OP_LESSTHANOREQUAL',
    0xa2: 'OP_GREATERTHANOREQUAL',
    0xa3: 'OP_MIN',
    0xa4: 'OP_MAX',
    0xa5: 'OP_WITHIN',

    // ZK precompile (Toccata, covenants_enabled)
    0xa6: 'OP_ZK_PRECOMPILE',

    // Crypto (Kaspa-specific layout — diverges from Bitcoin at 0xa7)
    0xa7: 'OP_BLAKE2B_WITH_KEY',     // covenants_enabled
    0xa8: 'OP_SHA256',
    0xa9: 'OP_CHECKMULTISIG_ECDSA',
    0xaa: 'OP_BLAKE2B',
    0xab: 'OP_CHECKSIG_ECDSA',
    0xac: 'OP_CHECKSIG',
    0xad: 'OP_CHECKSIGVERIFY',
    0xae: 'OP_CHECKMULTISIG',
    0xaf: 'OP_CHECKMULTISIGVERIFY',

    // Locktime
    0xb0: 'OP_CHECKLOCKTIMEVERIFY',
    0xb1: 'OP_CHECKSEQUENCEVERIFY',

    // KIP-10 / Covenant Introspection (TN12+)
    // Transaction-level
    0xb2: 'OP_TX_VERSION',           // covenants_enabled
    0xb3: 'OP_TX_INPUT_COUNT',       // always active
    0xb4: 'OP_TX_OUTPUT_COUNT',      // always active
    0xb5: 'OP_TX_LOCKTIME',          // covenants_enabled
    0xb6: 'OP_TX_SUBNET_ID',         // covenants_enabled
    0xb7: 'OP_TX_GAS',               // covenants_enabled
    0xb8: 'OP_TX_PAYLOAD_SUBSTR',    // covenants_enabled
    // Input-level
    0xb9: 'OP_TX_INPUT_INDEX',       // always active
    0xba: 'OP_OUTPOINT_TX_ID',       // covenants_enabled
    0xbb: 'OP_OUTPOINT_INDEX',       // covenants_enabled
    0xbc: 'OP_TX_INPUT_SCRIPT_SIG_SUBSTR', // covenants_enabled
    0xbd: 'OP_TX_INPUT_SEQ',         // covenants_enabled
    // UTXO-level
    0xbe: 'OP_TX_INPUT_AMOUNT',      // always active
    0xbf: 'OP_TX_INPUT_SPK',         // always active
    0xc0: 'OP_TX_INPUT_DAA_SCORE',   // covenants_enabled
    0xc1: 'OP_TX_INPUT_IS_COINBASE', // covenants_enabled
    // Output-level
    0xc2: 'OP_TX_OUTPUT_AMOUNT',     // always active
    0xc3: 'OP_TX_OUTPUT_SPK',        // always active
    // Extended introspection (covenants_enabled)
    0xc4: 'OP_TX_PAYLOAD_LEN',
    0xc5: 'OP_TX_INPUT_SPK_LEN',
    0xc6: 'OP_TX_INPUT_SPK_SUBSTR',
    0xc7: 'OP_TX_OUTPUT_SPK_LEN',
    0xc8: 'OP_TX_OUTPUT_SPK_SUBSTR',
    0xc9: 'OP_TX_INPUT_SCRIPT_SIG_LEN',
    // 0xca: invalid opcode
    // Auth / Covenant context opcodes (covenants_enabled)
    0xcb: 'OP_AUTH_OUTPUT_COUNT',
    0xcc: 'OP_AUTH_OUTPUT_IDX',
    0xcd: 'OP_NUM2BIN',
    0xce: 'OP_BIN2NUM',
    0xcf: 'OP_INPUT_COVENANT_ID',
    0xd0: 'OP_COV_INPUT_COUNT',
    0xd1: 'OP_COV_INPUT_IDX',
    0xd2: 'OP_COV_OUTPUT_COUNT',
    0xd3: 'OP_COV_OUTPUT_IDX',
    0xd4: 'OP_CHAINBLOCK_SEQ_COMMIT',
    // Output-level covenant context (Toccata, covenants_enabled)
    0xd5: 'OP_OUTPUT_COVENANT_ID',
    0xd6: 'OP_OUTPUT_AUTHORIZING_INPUT',
    // Stack-based signature verification (Toccata, covenants_enabled)
    0xd7: 'OP_CHECKSIG_FROM_STACK',
    0xd8: 'OP_CHECKSIG_FROM_STACK_ECDSA',
    // Blake3 hashing (Toccata, covenants_enabled)
    0xd9: 'OP_BLAKE3',
    0xda: 'OP_BLAKE3_WITH_KEY',
    // 0xdb-0xee: invalid / reserved
};

export function getOpDecode(op) {
    if (op >= 0x01 && op <= 0x4b) return `PUSH_${op}`;
    if (op === 0x4c) return 'OP_PUSHDATA1';
    if (op === 0x4d) return 'OP_PUSHDATA2';
    if (op === 0x4e) return 'OP_PUSHDATA4';
    return OP_MAP[op] || `0x${op.toString(16).toUpperCase().padStart(2, '0')}`;
}
