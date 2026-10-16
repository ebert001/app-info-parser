/**
 * Unit tests for lib/index.apk.js (AppInfoParserApk)
 * Tests the APK-only entry point.
 */
const AppInfoParserApk = require('../lib/index.apk')

describe('AppInfoParserApk constructor', () => {
  test('throws error when no file param is provided', () => {
    expect(() => new AppInfoParserApk()).toThrow('Param miss: file')
    expect(() => new AppInfoParserApk(null)).toThrow('Param miss: file')
    expect(() => new AppInfoParserApk('')).toThrow('Param miss: file')
  })

  test('throws error for non-APK file types', () => {
    expect(() => new AppInfoParserApk('test.ipa')).toThrow('only supports .apk')
    expect(() => new AppInfoParserApk('test.zip')).toThrow('only supports .apk')
    expect(() => new AppInfoParserApk('test.exe')).toThrow('only supports .apk')
  })

  test('accepts .apk file path without throwing', () => {
    expect(() => new AppInfoParserApk('test.apk')).not.toThrow()
  })

  test('file type detection is case-insensitive', () => {
    expect(() => new AppInfoParserApk('test.APK')).not.toThrow()
    expect(() => new AppInfoParserApk('test.Apk')).not.toThrow()
  })

  test('file type detection handles paths with dots', () => {
    expect(() => new AppInfoParserApk('/path/to/my.app.test.apk')).not.toThrow()
  })

  test('handles file object with name property (Browser-like)', () => {
    // In Node.js, Zip constructor expects string path, so it throws a different error.
    // We're testing that file type detection works via .name (not "Unsupported file type").
    const fakeFile = { name: 'test.apk', size: 1024 }
    expect(() => new AppInfoParserApk(fakeFile)).not.toThrow('Unsupported file type')
  })
})

describe('AppInfoParserApk internal parser', () => {
  test('creates ApkParser instance', () => {
    const parser = new AppInfoParserApk('test.apk')
    expect(parser.parser.constructor.name).toBe('ApkParser')
  })

  test('passes idsigFile option to ApkParser', () => {
    const parser = new AppInfoParserApk('test.apk', { idsigFile: 'test.idsig' })
    expect(parser.parser._idsigFile).toBe('test.idsig')
  })

  test('parse() method returns a Promise', () => {
    const parser = new AppInfoParserApk('test.apk')
    const result = parser.parse()
    expect(result).toBeInstanceOf(Promise)
    result.catch(() => {})
  })
})
