// Browser Buffer polyfill: ensure Buffer is available for signing block parsing.
// In Node.js, Buffer is global. In browser, the host app should provide it
// (e.g. via `import { Buffer } from 'buffer'` in main.ts).
// This fallback handles cases where the host app hasn't set it up.
if (typeof globalThis.Buffer === 'undefined') {
  try {
    globalThis.Buffer = require('buffer').Buffer
  } catch (e) {
    console.warn('[apk-parser-js] Buffer not available. V2/V3 certificate parsing will not work in browser.')
  }
}

const ApkParser = require('./apk')
const supportFileTypes = ['ipa', 'apk']

class AppInfoParser {
  /**
   * parser for parsing .ipa or .apk file
   * @param {String | File | Blob} file // file's path in Node, instance of File or Blob in browser
   * @param {Object} [options] // optional parameters
   * @param {String | File | Blob} [options.idsigFile] // .idsig file for V4 signature
   */
  constructor (file, options) {
    if (!file) {
      throw new Error('Param miss: file(file\'s path in Node, instance of File or Blob in browser).')
    }
    const splits = (file.name || file).split('.')
    const fileType = splits[splits.length - 1].toLowerCase()
    if (!supportFileTypes.includes(fileType)) {
      throw new Error('Unsupported file type, only support .ipa or .apk file.')
    }
    this.file = file
    const idsigFile = options && options.idsigFile ? options.idsigFile : null

    switch (fileType) {
      case 'ipa':
        // Lazy load: ipa.js depends on cgbi-to-png which requires Node.js stream/util.
        // Only load when actually parsing IPA files, so APK-only usage (e.g. in browsers)
        // never triggers the Node.js dependency chain.
        const IpaParser = require('./ipa')
        this.parser = new IpaParser(this.file)
        break
      case 'apk':
        this.parser = new ApkParser(this.file, idsigFile)
        break
    }
  }
  parse () {
    return this.parser.parse()
  }
}

module.exports = AppInfoParser
