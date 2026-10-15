/**
 * Unit tests for lib/cert-parser.js
 *
 * Tests certificate parsing utilities: PKCS#7 extraction, DN formatting,
 * error handling for invalid inputs, and full V1 signature flow.
 */

const { parseApkCert, extractCertsFromPkcs7 } = require('../lib/cert-parser')
const forge = require('node-forge')

// ---------------------------------------------------------------------------
// Helper: generate a self-signed X.509 certificate
// ---------------------------------------------------------------------------
function generateSelfSignedCert (overrides = {}) {
  const keys = forge.pki.rsa.generateKeyPair(1024)
  const cert = forge.pki.createCertificate()

  cert.publicKey = keys.publicKey
  cert.serialNumber = '01'
  cert.validity.notBefore = new Date('2020-01-01T00:00:00Z')
  cert.validity.notAfter = new Date('2030-01-01T00:00:00Z')

  const attrs = [
    { name: 'commonName', value: overrides.cn || 'TestCert' },
    { name: 'organizationName', value: overrides.o || 'TestOrg' },
    { name: 'countryName', value: overrides.c || 'CN' }
  ]
  cert.setSubject(attrs)
  cert.setIssuer(attrs) // self-signed
  cert.sign(keys.privateKey, forge.md.sha256.create())

  return { cert, keys, pem: forge.pki.certificateToPem(cert) }
}

// ---------------------------------------------------------------------------
// Helper: build a valid PKCS#7 SignedData buffer using forge
// Uses forge's own PKCS#7 API to create a proper structure,
// then extracts the raw DER for testing.
// ---------------------------------------------------------------------------
function buildValidPkcs7Buffer (certPem, keyPem) {
  const cert = forge.pki.certificateFromPem(certPem)

  // Build PKCS#7 SignedData manually using forge ASN.1
  const certAsn1 = forge.pki.certificateToAsn1(cert)

  // SignedData SEQUENCE
  const signedData = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    // version INTEGER
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
      forge.asn1.integerToDer(1)),
    // digestAlgorithms SET { AlgorithmIdentifier }
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
          forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()), // SHA-256
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
      ])
    ]),
    // contentInfo ContentInfo (data)
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
        forge.asn1.oidToDer('1.2.840.113549.1.7.1').getBytes()),
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, '')
      ])
    ]),
    // certificates [0] IMPLICIT SET OF Certificate
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      certAsn1
    ]),
    // signerInfos SET { SignerInfo }
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        // version
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
          forge.asn1.integerToDer(1)),
        // issuerAndSerialNumber
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.pki.distinguishedNameToAsn1(cert.issuer),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
            forge.asn1.integerToDer(parseInt(cert.serialNumber, 16) || 1))
        ]),
        // digestAlgorithm
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
            forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
        ]),
        // digestEncryptionAlgorithm
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
            forge.asn1.oidToDer('1.2.840.113549.1.1.1').getBytes()),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
        ]),
        // encryptedDigest (dummy 256-byte signature for RSA-2048)
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false,
          new Array(128).fill('\x00').join(''))
      ])
    ])
  ])

  // ContentInfo wrapping SignedData
  const contentInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
      forge.asn1.oidToDer('1.2.840.113549.1.7.2').getBytes()),
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      signedData
    ])
  ])

  const derBytes = forge.asn1.toDer(contentInfo)
  // Use base64 roundtrip to correctly convert forge ByteStringBuffer to Buffer
  const b64 = forge.util.encode64(derBytes.getBytes())
  return Buffer.from(b64, 'base64')
}

// ===========================================================================
// Tests
// ===========================================================================

describe('cert-parser', () => {
  describe('parseApkCert - error handling', () => {
    test('returns error when certRsaBuffer is null', () => {
      const result = parseApkCert(null, null, null)
      expect(result.signaturePass).toBe(false)
      expect(result.certChain).toEqual([])
      expect(result.error).toMatch(/No CERT\.RSA/)
    })

    test('returns error when certRsaBuffer is undefined', () => {
      const result = parseApkCert(undefined)
      expect(result.signaturePass).toBe(false)
      expect(result.certChain).toEqual([])
    })

    test('returns error for invalid/corrupt PKCS#7 data', () => {
      const garbage = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xFF])
      const result = parseApkCert(garbage)
      expect(result.signaturePass).toBe(false)
      expect(result.certChain).toEqual([])
      expect(result.error).toBeTruthy()
    })
  })

  describe('extractCertsFromPkcs7', () => {
    let certData, pkcs7Buffer

    beforeAll(() => {
      certData = generateSelfSignedCert({ cn: 'TestExtract', o: 'TestOrg', c: 'US' })
      pkcs7Buffer = buildValidPkcs7Buffer(certData.pem, certData.keys.privateKey)
    })

    test('extracts certificate from valid PKCS#7 buffer', () => {
      const certs = extractCertsFromPkcs7(pkcs7Buffer)
      expect(certs).toHaveLength(1)
      expect(certs[0]).toHaveProperty('pem')
      expect(certs[0]).toHaveProperty('subject')
      expect(certs[0]).toHaveProperty('issuer')
      expect(certs[0]).toHaveProperty('notBefore')
      expect(certs[0]).toHaveProperty('notAfter')
      expect(certs[0]).toHaveProperty('serialNumber')
      expect(certs[0]).toHaveProperty('isSelfSigned')
    })

    test('extracted certificate has correct DN fields', () => {
      const certs = extractCertsFromPkcs7(pkcs7Buffer)
      expect(certs[0].subject).toContain('CN=TestExtract')
      expect(certs[0].subject).toContain('O=TestOrg')
      expect(certs[0].subject).toContain('C=US')
    })

    test('self-signed certificate has matching subject and issuer', () => {
      const certs = extractCertsFromPkcs7(pkcs7Buffer)
      expect(certs[0].isSelfSigned).toBe(true)
      expect(certs[0].subject).toBe(certs[0].issuer)
    })

    test('extracted certificate has valid PEM format', () => {
      const certs = extractCertsFromPkcs7(pkcs7Buffer)
      expect(certs[0].pem).toContain('-----BEGIN CERTIFICATE-----')
      expect(certs[0].pem).toContain('-----END CERTIFICATE-----')
    })

    test('extracted certificate has validity dates', () => {
      const certs = extractCertsFromPkcs7(pkcs7Buffer)
      expect(certs[0].notBefore).toBe('2020-01-01T00:00:00.000Z')
      expect(certs[0].notAfter).toBe('2030-01-01T00:00:00.000Z')
    })

    test('throws for invalid buffer', () => {
      const garbage = Buffer.from([0x00, 0x01, 0x02])
      expect(() => extractCertsFromPkcs7(garbage)).toThrow()
    })
  })

  describe('parseApkCert with valid PKCS#7', () => {
    let certData, pkcs7Buffer

    beforeAll(() => {
      certData = generateSelfSignedCert({ cn: 'FullFlowTest' })
      pkcs7Buffer = buildValidPkcs7Buffer(certData.pem, certData.keys.privateKey)
    })

    test('returns certChain with extracted certificate', () => {
      const result = parseApkCert(pkcs7Buffer, null, null)
      expect(result.certChain.length).toBeGreaterThanOrEqual(1)
      expect(result.certChain[0].subject).toContain('CN=FullFlowTest')
    })

    test('returns signaturePass as boolean', () => {
      const result = parseApkCert(pkcs7Buffer, null, null)
      expect(typeof result.signaturePass).toBe('boolean')
    })

    test('certificate fields are compatible with apk.js mapping', () => {
      const result = parseApkCert(pkcs7Buffer, null, null)
      // Simulate what apk.js does: adds scheme field
      const mapped = result.certChain.map(c => ({ ...c, scheme: 'v1' }))
      expect(mapped[0].scheme).toBe('v1')
      expect(mapped[0].pem).toBeTruthy()
      expect(mapped[0].subject).toContain('CN=FullFlowTest')
      expect(mapped[0].issuer).toBeTruthy()
      expect(mapped[0].serialNumber).toBeTruthy()
    })
  })
})
