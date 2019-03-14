var Buffer = require('safe-buffer').Buffer
var bcrypto = require('./crypto')
var blake2b = require('blake2b')
var bscript = require('./script')
var bufferutils = require('./bufferutils')
var opcodes = require('bitcoin-ops')
var typeforce = require('typeforce')
var types = require('./types')
var varuint = require('varuint-bitcoin')
var networks = require('./networks')
var coins = require('./coins')

function varSliceSize (someScript) {
  var length = someScript.length

  return varuint.encodingLength(length) + length
}

function vectorSize (someVector) {
  var length = someVector.length

  return varuint.encodingLength(length) + someVector.reduce(function (sum, witness) {
    return sum + varSliceSize(witness)
  }, 0)
}

function Transaction (network) {
  this.version = 3
  this.locktime = 0
  this.timestamp = 0 // capricoin specific
  this.network = network || networks.zcash
  this.ins = []
  this.outs = []
  this.joinsplits = [] // zcash specific
  this.versionGroupId = '0x03c48270' // zcash specific
  this.expiry = 0 // zcash specific
  this.spendDescs = []; // zcash specific
  this.outputDescs = []; // zcash specific
  this.dashType = 0 // dash specific
  this.dashPayload = 0 // dash specific
  this.invalidTransaction = false;
}

Transaction.DEFAULT_SEQUENCE = 0xffffffff
Transaction.SIGHASH_ALL = 0x01
Transaction.SIGHASH_NONE = 0x02
Transaction.SIGHASH_SINGLE = 0x03
Transaction.SIGHASH_ANYONECANPAY = 0x80
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01

var EMPTY_SCRIPT = Buffer.allocUnsafe(0)
var EMPTY_WITNESS = []
var ZERO = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
var ONE = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex')
var VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex')
var BLANK_OUTPUT = {
  script: EMPTY_SCRIPT,
  valueBuffer: VALUE_UINT64_MAX
}

Transaction.ZCASH_OVERWINTER_VERSION = 3
Transaction.ZCASH_SAPLING_VERSION = 4
Transaction.ZCASH_JOINSPLITS_SUPPORT_VERSION = 2
Transaction.ZCASH_NUM_JS_INPUTS = 2
Transaction.ZCASH_NUM_JS_OUTPUTS = 2
Transaction.ZCASH_NOTECIPHERTEXT_SIZE = 1 + 8 + 32 + 32 + 512 + 16

Transaction.ZCASH_G1_PREFIX_MASK = 0x02
Transaction.ZCASH_G2_PREFIX_MASK = 0x0a

Transaction.DASH_NORMAL = 0
Transaction.DASH_PROVIDER_REGISTER = 1
Transaction.DASH_PROVIDER_UPDATE_SERVICE = 2
Transaction.DASH_PROVIDER_UPDATE_REGISTRAR = 3
Transaction.DASH_PROVIDER_UPDATE_REVOKE = 4
Transaction.DASH_COINBASE = 5
Transaction.DASH_QUORUM_COMMITMENT = 6

Transaction.PREVOUTS_HASH_PERSON = new Buffer('ZcashPrevoutHash')
Transaction.SEQUENCE_HASH_PERSON = new Buffer('ZcashSequencHash')
Transaction.OUTPUTS_HASH_PERSON = new Buffer('ZcashOutputsHash')
Transaction.JOINSPLITS_HASH_PERSON = new Buffer('ZcashJSplitsHash')
Transaction.OVERWINTER_HASH_PERSON = Buffer.concat([new Buffer('ZcashSigHash'), Buffer.from('191ba85b', 'hex')])

// Sapling note magic values, copied from src/zcash/Zcash.h
var NOTEENCRYPTION_AUTH_BYTES = 16;
var ZC_NOTEPLAINTEXT_LEADING = 1;
var ZC_V_SIZE = 8;
var ZC_RHO_SIZE = 32;
var ZC_R_SIZE = 32;
var ZC_MEMO_SIZE = 512;
var ZC_DIVERSIFIER_SIZE = 11;
var ZC_JUBJUB_POINT_SIZE = 32;
var ZC_JUBJUB_SCALAR_SIZE = 32;
var ZC_NOTEPLAINTEXT_SIZE = ZC_NOTEPLAINTEXT_LEADING + ZC_V_SIZE + ZC_RHO_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE;
var ZC_SAPLING_ENCPLAINTEXT_SIZE = ZC_NOTEPLAINTEXT_LEADING + ZC_DIVERSIFIER_SIZE + ZC_V_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE;
var ZC_SAPLING_OUTPLAINTEXT_SIZE = ZC_JUBJUB_POINT_SIZE + ZC_JUBJUB_SCALAR_SIZE;
var ZC_SAPLING_ENCCIPHERTEXT_SIZE = ZC_SAPLING_ENCPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES;
var ZC_SAPLING_OUTCIPHERTEXT_SIZE = ZC_SAPLING_OUTPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES;

Transaction.fromBuffer = function (buffer, network, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt8 () {
    var i = buffer.readUInt8(offset)
    offset += 1
    return i
  }

  function readUInt32 () {
    var i = buffer.readUInt32LE(offset)
    offset += 4
    return i
  }

  function readInt32 () {
    var i = buffer.readInt32LE(offset)
    offset += 4
    return i
  }

  function readUInt64 () {
    var i = bufferutils.readUInt64LE(buffer, offset)
    offset += 8
    return i
  }

  function readVarInt () {
    var vi = varuint.decode(buffer, offset)
    offset += varuint.decode.bytes
    return vi
  }

  function readVarSlice () {
    return readSlice(readVarInt())
  }

  function readVector () {
    var count = readVarInt()
    var vector = []
    for (var i = 0; i < count; i++) vector.push(readVarSlice())
    return vector
  }

  function readCompressedG1 () {
    var yLsb = readUInt8() & 1
    var x = readSlice(32)
    return {
      x: x,
      yLsb: yLsb
    }
  }

  function readCompressedG2 () {
    var yLsb = readUInt8() & 1
    var x = readSlice(64)
    return {
      x: x,
      yLsb: yLsb
    }
  }

  // zcash sapling
  function readSpentDesc () {
    var res = {};
    res.cv = readSlice(32);
    res.anchor = readSlice(32);
    res.nullifier = readSlice(32);
    res.rk = readSlice(32);
    res.proof = readSlice(48 + 96 + 48);
    res.spendAuthSig = readSlice(64);
    return res;
  }

  function readOutputDesc () {
    var res = {};
    res.cv = readSlice(32);
    res.cmu = readSlice(32);
    res.ephemeralKey = readSlice(32);
    res.encCipherText = readSlice(ZC_SAPLING_ENCCIPHERTEXT_SIZE);
    res.outCipherText = readSlice(ZC_SAPLING_OUTCIPHERTEXT_SIZE);
    res.proof = readSlice(48 + 96 + 48);
    return res;
  }

  var tx = new Transaction()
  tx.network = network || networks.bitcoin
  tx.version = readInt32()

  if (coins.isZcashLike(tx.network)) {
    var overwintered = tx.version >>> 31
    tx.version = tx.version & 0x7fffffff
    if (tx.version >= 3) {
      if (!overwintered) {
        throw new Error('zcash tx v3+ not overwintered')
      }
      tx.versionGroupId = readUInt32()
    }
  } else if(coins.isDash(tx.network)) {
    tx.dashType = tx.version >> 16
    tx.version = tx.version & 0xffff
    if (tx.version === 3 && (tx.dashType < Transaction.DASH_NORMAL || tx.dashType > Transaction.DASH_QUORUM_COMMITMENT)) {
      throw new Error('Unsupported Dash transaction type')
    }
  }

  var marker = buffer.readUInt8(offset)
  var flag = buffer.readUInt8(offset + 1)

  var hasWitnesses = false
  if (!coins.isZcashLike(tx.network)) {
    if (marker === Transaction.ADVANCED_TRANSACTION_MARKER &&
        flag === Transaction.ADVANCED_TRANSACTION_FLAG) {
      offset += 2
      hasWitnesses = true
    }
  }

  if (coins.isCapricoin(tx.network)) {
    tx.timestamp = readUInt32()
  }

  var vinLen = readVarInt()
  for (var i = 0; i < vinLen; ++i) {
    tx.ins.push({
      hash: readSlice(32),
      index: readUInt32(),
      script: readVarSlice(),
      sequence: readUInt32(),
      witness: EMPTY_WITNESS
    })
  }

  var voutLen = readVarInt()
  for (i = 0; i < voutLen; ++i) {
    tx.outs.push({
      value: readUInt64(),
      script: readVarSlice()
    })
  }

  if (hasWitnesses) {
    for (i = 0; i < vinLen; ++i) {
      tx.ins[i].witness = readVector()
    }

    // was this pointless?
    if (!tx.hasWitnesses()) throw new Error('Transaction has superfluous witness data')
  }

  tx.locktime = readUInt32()

  if (tx.isOverwinterCompatible()) {
    tx.expiry = readUInt32()
  }

  if (tx.isSaplingCompatible()) {
    tx.valueBalance = readUInt64();
    var sizeSpendDescs = readVarInt();
    for (var i = 0; i < sizeSpendDescs; i++) {
      var spend = readSpentDesc();
      tx.spendDescs.push(spend);
    }

    var sizeOutputDescs = readVarInt();
    for (var i = 0; i < sizeOutputDescs; i++) {
      var output = readOutputDesc();
      tx.outputDescs.push(output);
    }
  }

  if (tx.supportsJoinSplits()) {
    var jsLen = readVarInt()
    for (i = 0; i < jsLen; ++i) {
      var vpubOld = readUInt64()
      var vpubNew = readUInt64()
      var anchor = readSlice(32)
      var nullifiers = []
      for (var j = 0; j < Transaction.ZCASH_NUM_JS_INPUTS; j++) {
        nullifiers.push(readSlice(32))
      }
      var commitments = []
      for (j = 0; j < Transaction.ZCASH_NUM_JS_OUTPUTS; j++) {
        commitments.push(readSlice(32))
      }
      var ephemeralKey = readSlice(32)
      var randomSeed = readSlice(32)
      var macs = []
      for (j = 0; j < Transaction.ZCASH_NUM_JS_INPUTS; j++) {
        macs.push(readSlice(32))
      }
      var zproof = {};
      if (tx.version <= 3) {
        zproof = {
          gA: readCompressedG1(),
          gAPrime: readCompressedG1(),
          gB: readCompressedG2(),
          gBPrime: readCompressedG1(),
          gC: readCompressedG1(),
          gCPrime: readCompressedG1(),
          gK: readCompressedG1(),
          gH: readCompressedG1()
        }
      } else {
        zproof = {
          sA: readSlice(48),
          sB: readSlice(96),
          sC: readSlice(48)
        }
      }
      var ciphertexts = []
      for (j = 0; j < Transaction.ZCASH_NUM_JS_OUTPUTS; j++) {
        ciphertexts.push(readSlice(Transaction.ZCASH_NOTECIPHERTEXT_SIZE))
      }

      tx.joinsplits.push({
        vpubOld: vpubOld,
        vpubNew: vpubNew,
        anchor: anchor,
        nullifiers: nullifiers,
        commitments: commitments,
        ephemeralKey: ephemeralKey,
        randomSeed: randomSeed,
        macs: macs,
        zproof: zproof,
        ciphertexts: ciphertexts
      })
    }
    if (jsLen > 0) {
      tx.joinsplitPubkey = readSlice(32)
      tx.joinsplitSig = readSlice(64)
    }
    if (tx.isSaplingCompatible() && ((tx.spendDescs.length + tx.outputDescs.length) > 0)) {
      tx.bindingSig = readSlice(64);
    }
  }


  if (tx.isDashSpecialTransaction()) {
    tx.dashPayload = readVarSlice()
  }

  if (__noStrict) return tx
  if (offset !== buffer.length) throw new Error('Transaction has unexpected data')

  return tx
}

Transaction.fromHex = function (hex, network) {
  return Transaction.fromBuffer(new Buffer(hex, 'hex'), network)
}

Transaction.isCoinbaseHash = function (buffer) {
  typeforce(types.Hash256bit, buffer)
  for (var i = 0; i < 32; ++i) {
    if (buffer[i] !== 0) return false
  }
  return true
}

Transaction.prototype.isCoinbase = function () {
  return this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
}

Transaction.prototype.addInput = function (hash, index, sequence, scriptSig) {
  typeforce(types.tuple(
    types.Hash256bit,
    types.UInt32,
    types.maybe(types.UInt32),
    types.maybe(types.Buffer)
  ), arguments)

  if (types.Null(sequence)) {
    sequence = Transaction.DEFAULT_SEQUENCE
  }

  // Add the input and return the input's index
  return (this.ins.push({
    hash: hash,
    index: index,
    script: scriptSig || EMPTY_SCRIPT,
    sequence: sequence,
    witness: EMPTY_WITNESS
  }) - 1)
}

Transaction.prototype.addOutput = function (scriptPubKey, value) {
  typeforce(types.tuple(types.Buffer, types.Satoshi), arguments)

  // Add the output and return the output's index
  return (this.outs.push({
    script: scriptPubKey,
    value: value
  }) - 1)
}

Transaction.prototype.hasWitnesses = function () {
  return this.ins.some(function (x) {
    return x.witness.length !== 0
  })
}

Transaction.prototype.weight = function () {
  var base = this.__byteLength(false)
  var total = this.__byteLength(true)
  return base * 3 + total
}

Transaction.prototype.virtualSize = function () {
  return Math.ceil(this.weight() / 4)
}

Transaction.prototype.byteLength = function () {
  return this.__byteLength(true)
}

Transaction.prototype.joinsplitByteLength = function () {

  var joinSplitsLen = this.joinsplits.length
  var byteLength = 0
  byteLength += bufferutils.varIntSize(joinSplitsLen)  // vJoinSplit

  if (joinSplitsLen > 0) {
    // Both pre and post Sapling JoinSplits are encoded with the following data:
    // 8 vpub_old, 8 vpub_new, 32 anchor, joinSplitsLen * 32 nullifiers, joinSplitsLen * 32 commitments, 32 ephemeralKey
    // 32 ephemeralKey, 32 randomSeed, joinsplit.macs.length * 32 vmacs
    if (this.isSaplingCompatible()) {
      byteLength += 1698 * joinSplitsLen  // vJoinSplit using JSDescriptionGroth16
    } else {
      byteLength += 1802 * joinSplitsLen  // vJoinSplit using JSDescriptionPHGR13
    }
    byteLength += 32  // joinSplitPubKey
    byteLength += 64  // joinSplitSig
  }

  return byteLength
}

Transaction.prototype.spendDescsByteLength = function () {
  var byteLength = 0
  byteLength += varuint.encodingLength(this.spendDescs.length)  // nShieldedSpend
  byteLength += (384 * this.spendDescs.length)  // vShieldedSpend
  return byteLength
}

Transaction.prototype.outputDescsByteLength = function () {
  var byteLength = 0
  byteLength += varuint.encodingLength(this.outputDescs.length)  // nShieldedOutput
  byteLength += (948 * this.outputDescs.length)  // vShieldedOutput
  return byteLength
}

Transaction.prototype.zcashTransactionByteLength = function() {
  if (!coins.isZcashLike(this.network)) {
    throw new Error('zcashTransactionByteLength can only be called when using Zcash network')
  }
  var byteLength = 0
  byteLength += 4  // Header
  if (this.isOverwinterCompatible()) {
    byteLength += 4  // nVersionGroupId
  }
  byteLength += varuint.encodingLength(this.ins.length)  // tx_in_count
  byteLength += this.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script) }, 0)  // tx_in
  byteLength += varuint.encodingLength(this.outs.length)  // tx_out_count
  byteLength += this.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script) }, 0)  // tx_out
  byteLength += 4  // lock_time
  if (this.isOverwinterCompatible()) {
    byteLength += 4  // nExpiryHeight
  }
  if (this.isSaplingCompatible()) {
    byteLength += 8  // valueBalance
    byteLength += this.spendDescsByteLength()
    byteLength += this.outputDescsByteLength()
  }
  if (this.supportsJoinSplits()) {
    byteLength += this.joinsplitByteLength()
  }
  if (this.isSaplingCompatible() &&
    this.spendDescs.length + this.outputDescs.length > 0) {
    byteLength += 64  // bindingSig
  }
  return byteLength
}

Transaction.prototype.__byteLength = function (__allowWitness) {
  if (coins.isZcashLike(this.network)) {
    return this.zcashTransactionByteLength();
  }

  var hasWitnesses = __allowWitness && this.hasWitnesses()

  return (
    (hasWitnesses ? 10 : 8) +
    (this.timestamp ? 4 : 0) +
    varuint.encodingLength(this.ins.length) +
    varuint.encodingLength(this.outs.length) +
    this.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script) }, 0) +
    this.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script) }, 0) +
    (this.isDashSpecialTransaction() ? varSliceSize(this.dashPayload) : 0) +
    (hasWitnesses ? this.ins.reduce(function (sum, input) { return sum + vectorSize(input.witness) }, 0) : 0)
  )
}

// note - this is not updated for sapling and overwinter, do not use anywhere
Transaction.prototype.clone = function () {
  var newTx = new Transaction()
  newTx.version = this.version
  newTx.locktime = this.locktime
  newTx.timestamp = this.timestamp
  newTx.network = this.network
  newTx.dashType = this.dashType
  newTx.dashPayload = this.dashPayload
  newTx.invalidTransaction = this.invalidTransaction
  if (coins.isZcashLike(newTx.network)) {
    newTx.versionGroupId = this.versionGroupId
    newTx.expiry = this.expiry
  }
  newTx.ins = this.ins.map(function (txIn) {
    return {
      hash: txIn.hash,
      index: txIn.index,
      script: txIn.script,
      sequence: txIn.sequence,
      witness: txIn.witness
    }
  })

  newTx.outs = this.outs.map(function (txOut) {
    return {
      script: txOut.script,
      value: txOut.value
    }
  })

  return newTx
}

/**
 * Hash transaction for signing a specific input.
 *
 * Bitcoin uses a different hash for each signed transaction input.
 * This method copies the transaction, makes the necessary changes based on the
 * hashType, and then hashes the result.
 * This hash can then be used to sign the provided transaction input.
 */
Transaction.prototype.hashForSignature = function (inIndex, prevOutScript, hashType) {
  typeforce(types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number), arguments)

  // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
  if (inIndex >= this.ins.length) return ONE

  // ignore OP_CODESEPARATOR
  var ourScript = bscript.compile(bscript.decompile(prevOutScript).filter(function (x) {
    return x !== opcodes.OP_CODESEPARATOR
  }))

  var txTmp = this.clone()

  // SIGHASH_NONE: ignore all outputs? (wildcard payee)
  if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
    txTmp.outs = []

    // ignore sequence numbers (except at inIndex)
    txTmp.ins.forEach(function (input, i) {
      if (i === inIndex) return

      input.sequence = 0
    })

  // SIGHASH_SINGLE: ignore all outputs, except at the same index?
  } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
    if (inIndex >= this.outs.length) return ONE

    // truncate outputs after
    txTmp.outs.length = inIndex + 1

    // "blank" outputs before
    for (var i = 0; i < inIndex; i++) {
      txTmp.outs[i] = BLANK_OUTPUT
    }

    // ignore sequence numbers (except at inIndex)
    txTmp.ins.forEach(function (input, y) {
      if (y === inIndex) return

      input.sequence = 0
    })
  }

  // SIGHASH_ANYONECANPAY: ignore inputs entirely?
  if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
    txTmp.ins = [txTmp.ins[inIndex]]
    txTmp.ins[0].script = ourScript

  // SIGHASH_ALL: only ignore input scripts
  } else {
    // "blank" others input scripts
    txTmp.ins.forEach(function (input) { input.script = EMPTY_SCRIPT })
    txTmp.ins[inIndex].script = ourScript
  }

  // serialize and hash
  var buffer = Buffer.allocUnsafe(txTmp.__byteLength(false) + 4)
  buffer.writeInt32LE(hashType, buffer.length - 4)
  txTmp.__toBuffer(buffer, 0, false)

  return bcrypto.hash256(buffer)
}

Transaction.prototype.hashForZIP143 = function (inIndex, prevOutScript, value, hashType) {
  typeforce(types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32), arguments)

  var tbuffer, toffset
  function writeSlice (slice) { toffset += slice.copy(tbuffer, toffset) }
  function writeUInt32 (i) { toffset = tbuffer.writeUInt32LE(i, toffset) }
  function writeUInt64 (i) { toffset = bufferutils.writeUInt64LE(tbuffer, i, toffset) }
  function writeVarInt (i) {
    varuint.encode(i, tbuffer, toffset)
    toffset += varuint.encode.bytes
  }
  function writeVarSlice (slice) { writeVarInt(slice.length); writeSlice(slice) }

  var hashOutputs = ZERO
  var hashPrevouts = ZERO
  var hashSequence = ZERO
  var hashJoinsplits = ZERO
  var h

  if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
    tbuffer = Buffer.allocUnsafe(36 * this.ins.length)
    toffset = 0

    this.ins.forEach(function (txIn) {
      writeSlice(txIn.hash)
      writeUInt32(txIn.index)
    })

    h = blake2b(32, null, null, Transaction.PREVOUTS_HASH_PERSON)
    h.update(tbuffer)
    hashPrevouts = Buffer.from(h.digest())
  }

  if (!(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
       (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
       (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
    tbuffer = Buffer.allocUnsafe(4 * this.ins.length)
    toffset = 0

    this.ins.forEach(function (txIn) {
      writeUInt32(txIn.sequence)
    })

    h = blake2b(32, null, null, Transaction.SEQUENCE_HASH_PERSON)
    h.update(tbuffer)
    hashSequence = Buffer.from(h.digest())
  }

  if ((hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
    var txOutsSize = this.outs.reduce(function (sum, output) {
      return sum + 8 + varSliceSize(output.script)
    }, 0)

    tbuffer = Buffer.allocUnsafe(txOutsSize)
    toffset = 0

    this.outs.forEach(function (out) {
      writeUInt64(out.value)
      writeVarSlice(out.script)
    })

    h = blake2b(32, null, null, Transaction.OUTPUTS_HASH_PERSON)
    h.update(tbuffer)
    hashOutputs = Buffer.from(h.digest())
  } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE && inIndex < this.outs.length) {
    var output = this.outs[inIndex]

    tbuffer = Buffer.allocUnsafe(8 + varSliceSize(output.script))
    toffset = 0
    writeUInt64(output.value)
    writeVarSlice(output.script)

    h = blake2b(32, null, null, Transaction.OUTPUTS_HASH_PERSON)
    h.update(tbuffer)
    hashOutputs = Buffer.from(h.digest())
  }

  tbuffer = Buffer.allocUnsafe(196 + varSliceSize(prevOutScript))
  toffset = 0

  var input = this.ins[inIndex]
  writeUInt32(this.version + 0x80000000)
  writeUInt32(this.versionGroupId)
  writeSlice(hashPrevouts)
  writeSlice(hashSequence)
  writeSlice(hashOutputs)
  writeSlice(hashJoinsplits)
  writeUInt32(this.locktime)
  writeUInt32(this.expiry)
  writeUInt32(hashType)
  writeSlice(input.hash)
  writeUInt32(input.index)
  writeVarSlice(prevOutScript)
  writeUInt64(value)
  writeUInt32(input.sequence)
  h = blake2b(32, null, null, Transaction.OVERWINTER_HASH_PERSON)
  h.update(tbuffer)
  return Buffer.from(h.digest('hex'), 'hex')
}

Transaction.prototype.hashForWitnessV0 = function (inIndex, prevOutScript, value, hashType) {
  typeforce(types.tuple(types.UInt32, types.Buffer, types.Satoshi, types.UInt32), arguments)

  var tbuffer, toffset
  function writeSlice (slice) { toffset += slice.copy(tbuffer, toffset) }
  function writeUInt32 (i) { toffset = tbuffer.writeUInt32LE(i, toffset) }
  function writeUInt64 (i) { toffset = bufferutils.writeUInt64LE(tbuffer, i, toffset) }
  function writeVarInt (i) {
    varuint.encode(i, tbuffer, toffset)
    toffset += varuint.encode.bytes
  }
  function writeVarSlice (slice) { writeVarInt(slice.length); writeSlice(slice) }

  var hashOutputs = ZERO
  var hashPrevouts = ZERO
  var hashSequence = ZERO

  if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
    tbuffer = Buffer.allocUnsafe(36 * this.ins.length)
    toffset = 0

    this.ins.forEach(function (txIn) {
      writeSlice(txIn.hash)
      writeUInt32(txIn.index)
    })

    hashPrevouts = bcrypto.hash256(tbuffer)
  }

  if (!(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
       (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
       (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
    tbuffer = Buffer.allocUnsafe(4 * this.ins.length)
    toffset = 0

    this.ins.forEach(function (txIn) {
      writeUInt32(txIn.sequence)
    })

    hashSequence = bcrypto.hash256(tbuffer)
  }

  if ((hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE) {
    var txOutsSize = this.outs.reduce(function (sum, output) {
      return sum + 8 + varSliceSize(output.script)
    }, 0)

    tbuffer = Buffer.allocUnsafe(txOutsSize)
    toffset = 0

    this.outs.forEach(function (out) {
      writeUInt64(out.value)
      writeVarSlice(out.script)
    })

    hashOutputs = bcrypto.hash256(tbuffer)
  } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE && inIndex < this.outs.length) {
    var output = this.outs[inIndex]

    tbuffer = Buffer.allocUnsafe(8 + varSliceSize(output.script))
    toffset = 0
    writeUInt64(output.value)
    writeVarSlice(output.script)

    hashOutputs = bcrypto.hash256(tbuffer)
  }

  tbuffer = Buffer.allocUnsafe(156 + varSliceSize(prevOutScript))
  toffset = 0

  var input = this.ins[inIndex]
  writeUInt32(this.version)
  writeSlice(hashPrevouts)
  writeSlice(hashSequence)
  writeSlice(input.hash)
  writeUInt32(input.index)
  writeVarSlice(prevOutScript)
  writeUInt64(value)
  writeUInt32(input.sequence)
  writeSlice(hashOutputs)
  writeUInt32(this.locktime)
  writeUInt32(hashType)
  return bcrypto.hash256(tbuffer)
}

Transaction.prototype.getHash = function () {
  return bcrypto.hash256(this.__toBuffer(undefined, undefined, false))
}

Transaction.prototype.getId = function () {
  // transaction hash's are displayed in reverse order
  return this.getHash().reverse().toString('hex')
}

Transaction.prototype.toBuffer = function (buffer, initialOffset) {
  return this.__toBuffer(buffer, initialOffset, true)
}

Transaction.prototype.__toBuffer = function (buffer, initialOffset, __allowWitness) {
  if (!buffer) buffer = Buffer.allocUnsafe(this.__byteLength(__allowWitness))

  var offset = initialOffset || 0
  function writeSlice (slice) { offset += slice.copy(buffer, offset) }
  function writeUInt8 (i) { offset = buffer.writeUInt8(i, offset) }
  function writeUInt32 (i) { offset = buffer.writeUInt32LE(i, offset) }
  function writeInt16 (i) { offset = buffer.writeInt16LE(i, offset) }
  function writeInt32 (i) { offset = buffer.writeInt32LE(i, offset) }
  function writeUInt64 (i) { offset = bufferutils.writeUInt64LE(buffer, i, offset) }
  function writeVarInt (i) {
    varuint.encode(i, buffer, offset)
    offset += varuint.encode.bytes
  }
  function writeVarSlice (slice) { writeVarInt(slice.length); writeSlice(slice) }
  function writeVector (vector) { writeVarInt(vector.length); vector.forEach(writeVarSlice) }

  function writeCompressedG1 (i) {
    writeUInt8(Transaction.ZCASH_G1_PREFIX_MASK | i.yLsb)
    writeSlice(i.x)
  }

  function writeCompressedG2 (i) {
    writeUInt8(Transaction.ZCASH_G2_PREFIX_MASK | i.yLsb)
    writeSlice(i.x)
  }

  // zcash sapling
  function writeSpentDesc (i) {
    writeSlice(i.cv);
    writeSlice(i.anchor);
    writeSlice(i.nullifier);
    writeSlice(i.rk);
    writeSlice(i.proof);
    writeSlice(i.spendAuthSig);
  }

  function writeOutputDesc (i) {
    writeSlice(i.cv);
    writeSlice(i.cmu);
    writeSlice(i.ephemeralKey);
    writeSlice(i.encCipherText);
    writeSlice(i.outCipherText);
    writeSlice(i.proof);
  }

  if (this.isOverwinterCompatible()) {
    writeInt32(this.version | (1 << 31))
    writeUInt32(this.versionGroupId)
  } else if(this.isDashSpecialTransaction()) {
    writeInt16(this.version)
    writeInt16(this.dashType)
  } else {
    writeInt32(this.version)
  }

  var hasWitnesses = __allowWitness && this.hasWitnesses()

  if (hasWitnesses) {
    writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER)
    writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG)
  }

  if (this.timestamp) {
    writeUInt32(this.timestamp)
  }

  writeVarInt(this.ins.length)

  this.ins.forEach(function (txIn) {
    writeSlice(txIn.hash)
    writeUInt32(txIn.index)
    writeVarSlice(txIn.script)
    writeUInt32(txIn.sequence)
  })

  writeVarInt(this.outs.length)
  this.outs.forEach(function (txOut) {
    if (!txOut.valueBuffer) {
      writeUInt64(txOut.value)
    } else {
      writeSlice(txOut.valueBuffer)
    }

    writeVarSlice(txOut.script)
  })

  if (hasWitnesses) {
    this.ins.forEach(function (input) {
      writeVector(input.witness)
    })
  }

  writeUInt32(this.locktime)

  if (this.isOverwinterCompatible()) {
    writeUInt32(this.expiry)
  }

  if (this.isSaplingCompatible()) {
    writeUInt64(this.valueBalance);
    writeVarInt(this.spendDescs.length);
    for (var i = 0; i < this.spendDescs.length; i++) {
      writeSpentDesc(this.spendDescs[i]);
    }
    writeVarInt(this.outputDescs.length);
    for (var i = 0; i < this.outputDescs.length; i++) {
      writeOutputDesc(this.outputDescs[i]);
    }
  }

  if (this.supportsJoinSplits()) {
    writeVarInt(this.joinsplits.length)
    var version = this.version;
    this.joinsplits.forEach(function (joinsplit) {
      writeUInt64(joinsplit.vpubOld)
      writeUInt64(joinsplit.vpubNew)
      writeSlice(joinsplit.anchor)
      joinsplit.nullifiers.forEach(function (nullifier) {
        writeSlice(nullifier)
      })
      joinsplit.commitments.forEach(function (nullifier) {
        writeSlice(nullifier)
      })
      writeSlice(joinsplit.ephemeralKey)
      writeSlice(joinsplit.randomSeed)
      joinsplit.macs.forEach(function (nullifier) {
        writeSlice(nullifier)
      })
      if (version <= 3) {
        writeCompressedG1(joinsplit.zproof.gA)
        writeCompressedG1(joinsplit.zproof.gAPrime)
        writeCompressedG2(joinsplit.zproof.gB)
        writeCompressedG1(joinsplit.zproof.gBPrime)
        writeCompressedG1(joinsplit.zproof.gC)
        writeCompressedG1(joinsplit.zproof.gCPrime)
        writeCompressedG1(joinsplit.zproof.gK)
        writeCompressedG1(joinsplit.zproof.gH)
      } else {
        writeSlice(joinsplit.zproof.sA)
        writeSlice(joinsplit.zproof.sB)
        writeSlice(joinsplit.zproof.sC)
      }
      joinsplit.ciphertexts.forEach(function (ciphertext) {
        writeSlice(ciphertext)
      })
    })
    if (this.joinsplits.length > 0) {
      writeSlice(this.joinsplitPubkey)
      writeSlice(this.joinsplitSig)
    }
    if (this.isSaplingCompatible() && ((this.spendDescs.length + this.outputDescs.length) > 0)) {
      writeSlice(this.bindingSig);
    }
  }

  if (this.isDashSpecialTransaction()) {
    writeVarSlice(this.dashPayload)
  }

  // avoid slicing unless necessary
  if (initialOffset !== undefined) return buffer.slice(initialOffset, offset)
  return buffer
}

Transaction.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

Transaction.prototype.setInputScript = function (index, scriptSig) {
  typeforce(types.tuple(types.Number, types.Buffer), arguments)

  this.ins[index].script = scriptSig
}

Transaction.prototype.setWitness = function (index, witness) {
  typeforce(types.tuple(types.Number, [types.Buffer]), arguments)

  this.ins[index].witness = witness
}

Transaction.prototype.getExtraData = function () {
  if (this.supportsJoinSplits()) {
    var buffer = this.toBuffer()
    var joinsplitByteLength = this.joinsplitByteLength()
    var res = buffer.slice(buffer.length - joinsplitByteLength)
    return res
  }
  // if (coins.isDash(this.network) && this.dashPayload) {
  if (this.isDashSpecialTransaction()) {
    var extraDataLength = varuint.encode(this.dashPayload.length)
    return Buffer.concat([extraDataLength, this.dashPayload]);
  }
  return null
}

Transaction.prototype.isZcashTransaction = function () {
  return coins.isZcashLike(this.network)
}

Transaction.prototype.isSaplingCompatible = function () {
  return coins.isZcashLike(this.network) && this.version >= Transaction.ZCASH_SAPLING_VERSION
}

Transaction.prototype.isOverwinterCompatible = function () {
  return coins.isZcashLike(this.network) && this.version >= Transaction.ZCASH_OVERWINTER_VERSION
}

Transaction.prototype.supportsJoinSplits = function () {
  return coins.isZcashLike(this.network) && this.version >= Transaction.ZCASH_JOINSPLITS_SUPPORT_VERSION
}

Transaction.prototype.isDashSpecialTransaction = function () {
  return coins.isDash(this.network) && this.version === 3 && this.dashType !== Transaction.DASH_NORMAL
}

module.exports = Transaction
