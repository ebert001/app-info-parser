// IPA-only entry point
// Use this when you only need to parse IPA files (iOS).
// This avoids pulling in APK dependencies (bytebuffer, node-forge, etc.).

const IpaParser = require('./ipa')

class AppInfoParserIpa {
  /**
   * parser for parsing .ipa file
   * @param {String | File | Blob} file
   */
  constructor (file) {
    if (!file) {
      throw new Error('Param miss: file(file\'s path in Node, instance of File or Blob in browser).')
    }
    const splits = (file.name || file).split('.')
    const fileType = splits[splits.length - 1].toLowerCase()
    if (fileType !== 'ipa') {
      throw new Error('Unsupported file type, this build only supports .ipa file. Use the full build for .apk support.')
    }
    this.file = file
    this.parser = new IpaParser(this.file)
  }
  parse () {
    return this.parser.parse()
  }
}

module.exports = AppInfoParserIpa
