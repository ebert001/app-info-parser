// APK-only entry point
// Use this when you only need to parse APK files (Android).
// This avoids pulling in IPA dependencies (plist, bplist-parser, cgbi-to-png).

// Browser Buffer polyfill
if (typeof globalThis.Buffer === 'undefined') {
  try {
    globalThis.Buffer = require('buffer').Buffer
  } catch (e) {
    console.warn('[apk-parser-js] Buffer not available. V2/V3 certificate parsing will not work in browser.')
  }
}

const ApkParser = require('./apk')

class AppInfoParserApk {
  /**
   * parser for parsing .apk file
   * @param {String | File | Blob} file
   * @param {Object} [options]
   * @param {String | File | Blob} [options.idsigFile] // .idsig file for V4 signature
   */
  constructor (file, options) {
    if (!file) {
      throw new Error('Param miss: file(file\'s path in Node, instance of File or Blob in browser).')
    }
    const splits = (file.name || file).split('.')
    const fileType = splits[splits.length - 1].toLowerCase()
    if (fileType !== 'apk') {
      throw new Error('Unsupported file type, this build only supports .apk file. Use the full build for .ipa support.')
    }
    this.file = file
    const idsigFile = options && options.idsigFile ? options.idsigFile : null
    this.parser = new ApkParser(this.file, idsigFile)
  }
  parse () {
    return this.parser.parse()
  }
}

module.exports = AppInfoParserApk
