const ApkParser = require('./apk')
const IpaParser = require('./ipa')
const supportFileTypes = ['ipa', 'apk']

class AppInfoParser {
  /**
   * parser for parsing .ipa or .apk file
   * @param {String | File | Blob} file // file's path in Node, instance of File or Blob in Browser
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
