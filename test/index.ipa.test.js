/**
 * Unit tests for lib/index.ipa.js (AppInfoParserIpa)
 * Tests the IPA-only entry point.
 */
const AppInfoParserIpa = require('../lib/index.ipa')

describe('AppInfoParserIpa constructor', () => {
  test('throws error when no file param is provided', () => {
    expect(() => new AppInfoParserIpa()).toThrow('Param miss: file')
    expect(() => new AppInfoParserIpa(null)).toThrow('Param miss: file')
    expect(() => new AppInfoParserIpa('')).toThrow('Param miss: file')
  })

  test('throws error for non-IPA file types', () => {
    expect(() => new AppInfoParserIpa('test.apk')).toThrow('only supports .ipa')
    expect(() => new AppInfoParserIpa('test.zip')).toThrow('only supports .ipa')
    expect(() => new AppInfoParserIpa('test.exe')).toThrow('only supports .ipa')
  })

  test('accepts .ipa file path without throwing', () => {
    expect(() => new AppInfoParserIpa('test.ipa')).not.toThrow()
  })

  test('file type detection is case-insensitive', () => {
    expect(() => new AppInfoParserIpa('test.IPA')).not.toThrow()
    expect(() => new AppInfoParserIpa('test.Ipa')).not.toThrow()
  })

  test('file type detection handles paths with dots', () => {
    expect(() => new AppInfoParserIpa('/path/to/my.app.v2.0.ipa')).not.toThrow()
  })

  test('handles file object with name property (Browser-like)', () => {
    // In Node.js, Zip constructor expects string path, so it throws a different error.
    // We're testing that file type detection works via .name (not "Unsupported file type").
    const fakeFile = { name: 'test.ipa', size: 1024 }
    expect(() => new AppInfoParserIpa(fakeFile)).not.toThrow('Unsupported file type')
  })
})

describe('AppInfoParserIpa internal parser', () => {
  test('creates IpaParser instance', () => {
    const parser = new AppInfoParserIpa('test.ipa')
    expect(parser.parser.constructor.name).toBe('IpaParser')
  })

  test('parse() method returns a Promise', () => {
    const parser = new AppInfoParserIpa('test.ipa')
    const result = parser.parse()
    expect(result).toBeInstanceOf(Promise)
    result.catch(() => {})
  })
})
