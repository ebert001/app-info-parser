/**
 * Unit tests for lib/apk-idsig.js
 *
 * Tests V4 signature (.idsig file) parsing: protobuf wire format,
 * certificate extraction, and error handling.
 */

const { parseIdsig } = require('../lib/apk-idsig')
const forge = require('node-forge')

// ---------------------------------------------------------------------------
// Helper: generate a self-signed certificate
// ---------------------------------------------------------------------------
function generateSelfSignedCert (cn = 'TestCert') {
  const keys = forge.pki.rsa.generateKeyPair(1024)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date('2020-01-01T00:00:00Z')
  cert.validity.notAfter = new Date('2030-01-01T00:00:00Z')
  const attrs = [
    { name: 'commonName', value: cn },
    { name: 'organizationName', value: 'TestOrg' },
    { name: 'countryName', value: 'CN' }
  ]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)
  cert.sign(keys.privateKey, forge.md.sha256.create())
  return { cert, keys, pem: forge.pki.certificateToPem(cert) }
}

// ---------------------------------------------------------------------------
// Helper: get DER bytes of a certificate
// ---------------------------------------------------------------------------
function getCertDerBytes (certPem) {
  const cert = forge.pki.certificateFromPem(certPem)
  const certAsn1 = forge.pki.certificateToAsn1(cert)
  const certDer = forge.asn1.toDer(certAsn1)
  // Use base64 roundtrip to correctly convert forge ByteStringBuffer to Buffer
  const b64 = forge.util.encode64(certDer.getBytes())
  return Buffer.from(b64, 'base64')
}

// ---------------------------------------------------------------------------
// Helper: encode a protobuf varint
// ---------------------------------------------------------------------------
function encodeVarint (value) {
  const bytes = []
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80)
    value >>>= 7
  }
  bytes.push(value & 0x7f)
  return Buffer.from(bytes)
}

// ---------------------------------------------------------------------------
// Helper: encode a protobuf length-delimited field
// ---------------------------------------------------------------------------
function encodeLengthDelimited (fieldNumber, data) {
  const tag = encodeVarint((fieldNumber << 3) | 2)
  const length = encodeVarint(data.length)
  return Buffer.concat([tag, length, data])
}

// ---------------------------------------------------------------------------
// Helper: encode a protobuf varint field
// ---------------------------------------------------------------------------
function encodeVarintField (fieldNumber, value) {
  const tag = encodeVarint((fieldNumber << 3) | 0)
  const val = encodeVarint(value)
  return Buffer.concat([tag, val])
}

// ---------------------------------------------------------------------------
// Helper: build a minimal .idsig protobuf buffer
// ---------------------------------------------------------------------------
function buildIdsigBuffer (certDerBuffers) {
  // AuthorizingSection (field 3 of outer):
  //   field 2: repeated bytes certificate_chain (DER-encoded)
  let authSection = Buffer.alloc(0)
  for (const certDer of certDerBuffers) {
    authSection = Buffer.concat([authSection, encodeLengthDelimited(2, certDer)])
  }

  // Outer Idsig message:
  //   field 1: int32 version
  //   field 3: AuthorizingSection (embedded message)
  let outer = Buffer.alloc(0)
  outer = Buffer.concat([outer, encodeVarintField(1, 1)]) // version = 1
  outer = Buffer.concat([outer, encodeLengthDelimited(3, authSection)])

  return outer
}

// ===========================================================================
// Tests
// ===========================================================================

describe('apk-idsig', () => {
  describe('parseIdsig - error handling', () => {
    test('returns error for null buffer', () => {
      const result = parseIdsig(null)
      expect(result.signaturePass).toBe(false)
      expect(result.certChain).toEqual([])
      expect(result.error).toBeTruthy()
    })

    test('returns error for empty buffer', () => {
      const result = parseIdsig(Buffer.alloc(0))
      expect(result.signaturePass).toBe(false)
      expect(result.certChain).toEqual([])
    })

    test('returns error for garbage data', () => {
      const result = parseIdsig(Buffer.from([0xFF, 0xFE, 0xFD]))
      // Should either error or return no certs
      expect(result.certChain).toEqual([])
    })

    test('returns empty certChain when no AuthorizingSection', () => {
      // Build a protobuf with only version field, no AuthorizingSection
      const buf = encodeVarintField(1, 1) // version = 1 only
      const result = parseIdsig(buf)
      expect(result.version).toBe(1)
      expect(result.certChain).toEqual([])
      expect(result.error).toMatch(/No AuthorizingSection/)
    })
  })

  describe('parseIdsig - certificate extraction', () => {
    let certData, certDerBytes, idsigBuffer

    beforeAll(() => {
      certData = generateSelfSignedCert('V4TestCert')
      certDerBytes = getCertDerBytes(certData.pem)
      idsigBuffer = buildIdsigBuffer([certDerBytes])
    })

    test('extracts certificate from valid .idsig buffer', () => {
      const result = parseIdsig(idsigBuffer)
      expect(result.certChain).toHaveLength(1)
      expect(result.signaturePass).toBe(true)
    })

    test('extracted certificate has all required fields', () => {
      const result = parseIdsig(idsigBuffer)
      const cert = result.certChain[0]
      expect(cert).toHaveProperty('pem')
      expect(cert).toHaveProperty('subject')
      expect(cert).toHaveProperty('issuer')
      expect(cert).toHaveProperty('notBefore')
      expect(cert).toHaveProperty('notAfter')
      expect(cert).toHaveProperty('serialNumber')
      expect(cert).toHaveProperty('isSelfSigned')
    })

    test('extracted certificate has correct DN', () => {
      const result = parseIdsig(idsigBuffer)
      expect(result.certChain[0].subject).toContain('CN=V4TestCert')
      expect(result.certChain[0].subject).toContain('O=TestOrg')
    })

    test('extracted certificate has valid PEM', () => {
      const result = parseIdsig(idsigBuffer)
      expect(result.certChain[0].pem).toContain('-----BEGIN CERTIFICATE-----')
      expect(result.certChain[0].pem).toContain('-----END CERTIFICATE-----')
    })

    test('extracted certificate has validity dates', () => {
      const result = parseIdsig(idsigBuffer)
      expect(result.certChain[0].notBefore).toBe('2020-01-01T00:00:00.000Z')
      expect(result.certChain[0].notAfter).toBe('2030-01-01T00:00:00.000Z')
    })

    test('self-signed certificate is detected', () => {
      const result = parseIdsig(idsigBuffer)
      expect(result.certChain[0].isSelfSigned).toBe(true)
    })

    test('version field is parsed correctly', () => {
      const result = parseIdsig(idsigBuffer)
      expect(result.version).toBe(1)
    })
  })

  describe('parseIdsig - multiple certificates', () => {
    test('extracts multiple certificates from .idsig', () => {
      const cert1 = generateSelfSignedCert('Cert1')
      const cert2 = generateSelfSignedCert('Cert2')
      const der1 = getCertDerBytes(cert1.pem)
      const der2 = getCertDerBytes(cert2.pem)
      const idsigBuffer = buildIdsigBuffer([der1, der2])

      const result = parseIdsig(idsigBuffer)
      expect(result.certChain).toHaveLength(2)
      expect(result.certChain[0].subject).toContain('CN=Cert1')
      expect(result.certChain[1].subject).toContain('CN=Cert2')
      expect(result.signaturePass).toBe(true)
    })
  })

  describe('parseIdsig - accepts various input types', () => {
    test('accepts Uint8Array input', () => {
      const certData = generateSelfSignedCert('Uint8Test')
      const derBytes = getCertDerBytes(certData.pem)
      const idsigBuffer = buildIdsigBuffer([derBytes])
      const uint8 = new Uint8Array(idsigBuffer)

      const result = parseIdsig(uint8)
      expect(result.certChain).toHaveLength(1)
      expect(result.certChain[0].subject).toContain('CN=Uint8Test')
    })

    test('accepts ArrayBuffer input', () => {
      const certData = generateSelfSignedCert('ABTest')
      const derBytes = getCertDerBytes(certData.pem)
      const idsigBuffer = buildIdsigBuffer([derBytes])
      const ab = idsigBuffer.buffer.slice(
        idsigBuffer.byteOffset,
        idsigBuffer.byteOffset + idsigBuffer.byteLength
      )

      const result = parseIdsig(ab)
      expect(result.certChain).toHaveLength(1)
      expect(result.certChain[0].subject).toContain('CN=ABTest')
    })
  })
})
