const Zip = require('./zip')
const { mapInfoResource, findApkIconPath, getBase64FromBuffer } = require('./utils')
const { parseApkCert } = require('./cert-parser')
const { parseApkSigningBlock } = require('./apk-signing-block')
const { parseIdsig } = require('./apk-idsig')
const ManifestName = /^androidmanifest\.xml$/
const ResourceName = /^resources\.arsc$/
const CertRsaName = /^META-INF\/.*\.RSA$/i
const ManifestMfName = /^META-INF\/MANIFEST\.MF$/i
const CertSfName = /^META-INF\/.*\.SF$/i

const ManifestXmlParser = require('./xml-parser/manifest')
const ResourceFinder = require('./resource-finder')

class ApkParser extends Zip {
  /**
   * parser for parsing .apk file
   * @param {String | File | Blob} file // file's path in Node, instance of File or Blob in Browser
   * @param {String | File | Blob} [idsigFile] // optional .idsig file for V4 signature
   */
  constructor (file, idsigFile) {
    super(file)
    this._idsigFile = idsigFile || null
    if (!(this instanceof ApkParser)) {
      return new ApkParser(file, idsigFile)
    }
  }
  parse () {
    return new Promise((resolve, reject) => {
      this.getEntries([ManifestName, ResourceName, CertRsaName, ManifestMfName, CertSfName]).then(buffers => {
        if (!buffers[ManifestName]) {
          throw new Error('AndroidManifest.xml can\'t be found.')
        }
        let apkInfo = this._parseManifest(buffers[ManifestName])
        let resourceMap
        if (!buffers[ResourceName]) {
          // No resources.arsc — still try cert parsing
          apkInfo = this._parseCertAndResolve(apkInfo, buffers, resolve)
        } else {
          // parse resourceMap
          resourceMap = this._parseResourceMap(buffers[ResourceName])
          // update apkInfo with resourceMap
          apkInfo = mapInfoResource(apkInfo, resourceMap)

          // find icon path and parse icon
          const iconPath = findApkIconPath(apkInfo)
          if (iconPath) {
            this.getEntry(iconPath).then(iconBuffer => {
              apkInfo.icon = iconBuffer ? getBase64FromBuffer(iconBuffer) : null
              // Parse certificate/signature
              apkInfo = this._parseCertAndResolve(apkInfo, buffers, resolve)
            }).catch(e => {
              apkInfo.icon = null
              apkInfo = this._parseCertAndResolve(apkInfo, buffers, resolve)
              console.warn('[Warning] failed to parse icon: ', e)
            })
          } else {
            apkInfo.icon = null
            apkInfo = this._parseCertAndResolve(apkInfo, buffers, resolve)
          }
        }
      }).catch(e => {
        reject(e)
      })
    })
  }

  /**
   * Parse certificate/signature info and resolve the promise.
   * This is called after icon parsing to ensure all info is collected.
   */
  _parseCertAndResolve (apkInfo, buffers, resolve) {
    // Collect certificates from ALL signature schemes (V1, V2, V3)
    this._readRawFile().then(async rawBuffer => {
      const allCerts = []
      const schemes = []
      let anyPass = false
      let firstError = null

      // 1. Try V4 (.idsig file)
      if (this._idsigFile) {
        try {
          const idsigBuffer = await this._readIdsigFile()
          if (idsigBuffer) {
            const v4Result = parseIdsig(idsigBuffer)
            if (v4Result.certChain && v4Result.certChain.length > 0) {
              for (const cert of v4Result.certChain) {
                allCerts.push({ ...cert, scheme: 'v4' })
              }
              schemes.push('v4')
              if (v4Result.signaturePass) anyPass = true
            }
            if (v4Result.error && !firstError) firstError = v4Result.error
          }
        } catch (e) {
          if (!firstError) firstError = e.message || String(e)
        }
      }

      // 2. Try V2/V3 (APK Signing Block)
      if (rawBuffer) {
        try {
          const { findSigningBlock } = require('./apk-signing-block')
          const { parseSignatureBlock } = require('./apk-signing-block')
          const block = findSigningBlock(rawBuffer)
          if (block) {
            // Parse V2
            const v2Pair = block.pairs.find(p => p.id === 0x7109871a)
            if (v2Pair) {
              const v2Data = rawBuffer.slice(v2Pair.offset, v2Pair.offset + v2Pair.length)
              const signers = parseSignatureBlock(v2Data, 2)
              for (const signer of signers) {
                for (const cert of signer.certs) {
                  allCerts.push({ ...cert, scheme: 'v2' })
                }
              }
              if (signers.length > 0 && signers[0].certs.length > 0) schemes.push('v2')
            }
            // Parse V3
            const v3Pair = block.pairs.find(p => p.id === 0xf05368c0)
            if (v3Pair) {
              const v3Data = rawBuffer.slice(v3Pair.offset, v3Pair.offset + v3Pair.length)
              const signers = parseSignatureBlock(v3Data, 3)
              for (const signer of signers) {
                for (const cert of signer.certs) {
                  allCerts.push({ ...cert, scheme: 'v3' })
                }
              }
              if (signers.length > 0 && signers[0].certs.length > 0) schemes.push('v3')
            }
          }
        } catch (e) {
          if (!firstError) firstError = e.message || String(e)
        }
      }

      // 3. Try V1 (JAR signing via META-INF/CERT.RSA)
      try {
        const v1Result = parseApkCert(
          buffers[CertRsaName],
          buffers[ManifestMfName],
          buffers[CertSfName]
        )
        if (v1Result.certChain && v1Result.certChain.length > 0) {
          for (const cert of v1Result.certChain) {
            allCerts.push({ ...cert, scheme: 'v1' })
          }
          schemes.push('v1')
          if (v1Result.signaturePass) anyPass = true
        }
        if (v1Result.error && !firstError) firstError = v1Result.error
      } catch (e) {
        if (!firstError) firstError = e.message || String(e)
      }

      // V2/V3: if certificates were extracted, signature scheme is present
      if (schemes.includes('v2') || schemes.includes('v3')) {
        anyPass = true
      }

      // Build result
      apkInfo.certChain = allCerts.map(c => ({
        pem: c.pem,
        subject: c.subject,
        issuer: c.issuer,
        notBefore: c.notBefore,
        notAfter: c.notAfter,
        serialNumber: c.serialNumber,
        isSelfSigned: c.isSelfSigned,
        scheme: c.scheme
      }))
      apkInfo.signaturePass = anyPass
      apkInfo.signatureScheme = schemes.length > 0 ? schemes.join('/') : null
      if (firstError && allCerts.length === 0) {
        apkInfo.certError = firstError
      }
      resolve(apkInfo)
    }).catch(e => {
      // If raw file reading fails, just try V1
      try {
        const certResult = parseApkCert(
          buffers[CertRsaName],
          buffers[ManifestMfName],
          buffers[CertSfName]
        )
        apkInfo.signaturePass = certResult.signaturePass
        apkInfo.certChain = (certResult.certChain || []).map(c => ({ ...c, scheme: 'v1' }))
        apkInfo.signatureScheme = certResult.certChain && certResult.certChain.length ? 'v1' : null
        if (certResult.error) apkInfo.certError = certResult.error
      } catch (e2) {
        apkInfo.signaturePass = false
        apkInfo.certChain = []
        apkInfo.certError = e2.message || String(e2)
      }
      resolve(apkInfo)
    })
    return apkInfo
  }

  /**
   * Read the entire raw APK file as a Buffer.
   * In Node.js, reads from file path. In browser, reads from Blob/File.
   * Returns a Promise<Buffer>.
   */
  _readRawFile () {
    return new Promise((resolve, reject) => {
      if (typeof Buffer !== 'undefined' && typeof this.file === 'string') {
        // Node.js: read from file path
        try {
          const fs = require('fs')
          const buf = fs.readFileSync(this.file)
          resolve(buf)
        } catch (e) {
          resolve(null)
        }
      } else if (typeof Blob !== 'undefined' && this.file instanceof Blob) {
        // Browser: read from Blob/File
        if (this.file.arrayBuffer) {
          this.file.arrayBuffer().then(ab => resolve(Buffer.from(ab))).catch(() => resolve(null))
        } else {
          const reader = new FileReader()
          reader.onload = () => resolve(Buffer.from(reader.result))
          reader.onerror = () => resolve(null)
          reader.readAsArrayBuffer(this.file)
        }
      } else {
        resolve(null)
      }
    })
  }
  /**
   * Read the .idsig file as a Buffer (for V4 signature).
   * In Node.js, reads from file path. In browser, reads from Blob/File.
   * Returns a Promise<Buffer|null>.
   */
  _readIdsigFile () {
    return new Promise((resolve, reject) => {
      if (!this._idsigFile) {
        resolve(null)
        return
      }
      if (typeof Buffer !== 'undefined' && typeof this._idsigFile === 'string') {
        // Node.js: read from file path
        try {
          const fs = require('fs')
          const buf = fs.readFileSync(this._idsigFile)
          resolve(buf)
        } catch (e) {
          resolve(null)
        }
      } else if (typeof Blob !== 'undefined' && this._idsigFile instanceof Blob) {
        // Browser: read from Blob/File
        if (this._idsigFile.arrayBuffer) {
          this._idsigFile.arrayBuffer().then(ab => resolve(Buffer.from(ab))).catch(() => resolve(null))
        } else {
          const reader = new FileReader()
          reader.onload = () => resolve(Buffer.from(reader.result))
          reader.onerror = () => resolve(null)
          reader.readAsArrayBuffer(this._idsigFile)
        }
      } else {
        resolve(null)
      }
    })
  }
  /**
   * Parse manifest
   * @param {Buffer} buffer // manifest file's buffer
   */
  _parseManifest (buffer) {
    try {
      const parser = new ManifestXmlParser(buffer, {
        ignore: [
          'application.activity',
          'application.service',
          'application.receiver',
          'application.provider',
          'permission-group'
        ]
      })
      return parser.parse()
    } catch (e) {
      throw new Error('Parse AndroidManifest.xml error: ', e)
    }
  }
  /**
   * Parse resourceMap
   * @param {Buffer} buffer // resourceMap file's buffer
   */
  _parseResourceMap (buffer) {
    try {
      return new ResourceFinder().processResourceTable(buffer)
    } catch (e) {
      throw new Error('Parser resources.arsc error: ' + e)
    }
  }
}

module.exports = ApkParser
