/**
 * APK Signature Scheme V4 Parser
 *
 * Parses .idsig files (protobuf format) to extract certificate chains
 * from APK Signature Scheme V4.
 *
 * V4 differs from V2/V3: the signature is stored in a separate .idsig file
 * alongside the APK, not inside the APK itself.
 *
 * Reference:
 *   https://source.android.com/docs/security/features/apksigning/v4
 */

const forge = require('node-forge')

// ---------------------------------------------------------------------------
// Buffer helpers
// ---------------------------------------------------------------------------

function bufferToBinary (buf) {
  if (buf instanceof ArrayBuffer) buf = new Uint8Array(buf)
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(buf)) {
    return buf.toString('binary')
  }
  let s = ''
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i])
  return s
}

/**
 * Format an X.509 distinguished name as a full DN string.
 */
function extractDnName (dn) {
  return dn.attributes.map(a => a.shortName + '=' + a.value).join(', ')
}

// ---------------------------------------------------------------------------
// Protobuf wire format parser (minimal, for .idsig only)
// ---------------------------------------------------------------------------

/**
 * Parse protobuf wire format fields from a buffer.
 * Returns array of { fieldNumber, wireType, data }
 *   wireType 0 = varint, data = number
 *   wireType 2 = length-delimited, data = Buffer slice
 */
function parseProtobufFields (buf) {
  const fields = []
  let offset = 0

  while (offset < buf.length) {
    // Read tag (varint)
    let tag = 0
    let shift = 0
    while (offset < buf.length) {
      const b = buf[offset++]
      tag |= (b & 0x7f) << shift
      if ((b & 0x80) === 0) break
      shift += 7
    }

    const fieldNumber = tag >>> 3
    const wireType = tag & 0x07

    if (wireType === 0) {
      // Varint
      let value = 0
      let s = 0
      while (offset < buf.length) {
        const b = buf[offset++]
        value |= (b & 0x7f) << s
        if ((b & 0x80) === 0) break
        s += 7
      }
      fields.push({ fieldNumber, wireType, data: value })
    } else if (wireType === 2) {
      // Length-delimited
      let length = 0
      let s = 0
      while (offset < buf.length) {
        const b = buf[offset++]
        length |= (b & 0x7f) << s
        if ((b & 0x80) === 0) break
        s += 7
      }
      const data = buf.slice(offset, offset + length)
      offset += length
      fields.push({ fieldNumber, wireType, data })
    } else if (wireType === 1) {
      // 64-bit: skip 8 bytes
      offset += 8
      fields.push({ fieldNumber, wireType, data: null })
    } else if (wireType === 5) {
      // 32-bit: skip 4 bytes
      offset += 4
      fields.push({ fieldNumber, wireType, data: null })
    } else {
      // Unknown wire type, stop parsing
      break
    }
  }

  return fields
}

// ---------------------------------------------------------------------------
// Certificate parsing
// ---------------------------------------------------------------------------

/**
 * Parse a DER-encoded X.509 certificate buffer.
 * Returns { pem, subject, issuer, notBefore, notAfter, serialNumber, isSelfSigned }
 */
function parseCertDer (certDerBuf) {
  const certBinary = bufferToBinary(certDerBuf)
  const certAsn1 = forge.asn1.fromDer(certBinary)
  const cert = forge.pki.certificateFromAsn1(certAsn1)
  const pem = forge.pki.certificateToPem(cert)

  return {
    pem,
    subject: extractDnName(cert.subject),
    issuer: extractDnName(cert.issuer),
    notBefore: cert.validity.notBefore.toISOString(),
    notAfter: cert.validity.notAfter.toISOString(),
    serialNumber: cert.serialNumber,
    isSelfSigned:
      forge.pki.distinguishedNameToAsn1(cert.subject).toString() ===
      forge.pki.distinguishedNameToAsn1(cert.issuer).toString()
  }
}

// ---------------------------------------------------------------------------
// .idsig parsing
// ---------------------------------------------------------------------------

/**
 * Parse an .idsig file buffer (protobuf format) and extract certificate chain.
 *
 * Idsig protobuf structure:
 *   field 1: int32 version
 *   field 2: SigningScheme (embedded message)
 *   field 3: AuthorizingSection (embedded message)
 *     field 2: repeated bytes certificate_chain (DER-encoded X.509)
 *     field 3: SignedData (embedded message)
 *     field 4: bytes public_key
 *
 * @param {Buffer|Uint8Array} idsigBuffer - The .idsig file content
 * @returns {{
 *   version: number,
 *   certChain: Array,
 *   signaturePass: boolean,
 *   error?: string
 * }}
 */
function parseIdsig (idsigBuffer) {
  try {
    const buf = Buffer.isBuffer(idsigBuffer) ? idsigBuffer : Buffer.from(idsigBuffer)

    // Parse outer Idsig message
    const outerFields = parseProtobufFields(buf)

    let version = 0
    let authorizingSectionBuf = null

    for (const field of outerFields) {
      if (field.fieldNumber === 1 && field.wireType === 0) {
        version = field.data
      } else if (field.fieldNumber === 3 && field.wireType === 2) {
        authorizingSectionBuf = field.data
      }
    }

    if (!authorizingSectionBuf) {
      return {
        version,
        certChain: [],
        signaturePass: false,
        error: 'No AuthorizingSection found in .idsig file'
      }
    }

    // Parse AuthorizingSection message
    const authFields = parseProtobufFields(authorizingSectionBuf)
    const certDerBuffers = []

    for (const field of authFields) {
      // field 2 = certificate_chain (repeated bytes, wireType 2)
      if (field.fieldNumber === 2 && field.wireType === 2 && field.data) {
        certDerBuffers.push(field.data)
      }
    }

    // Parse each certificate
    const certChain = []
    for (const certDerBuf of certDerBuffers) {
      if (certDerBuf.length > 0) {
        try {
          certChain.push(parseCertDer(certDerBuf))
        } catch (certErr) {
          // Skip unparseable certificates
        }
      }
    }

    // Signature pass: certificates extracted = signature scheme present
    return {
      version,
      certChain,
      signaturePass: certChain.length > 0
    }
  } catch (e) {
    return {
      version: 0,
      certChain: [],
      signaturePass: false,
      error: e.message || String(e)
    }
  }
}

module.exports = {
  parseIdsig
}
