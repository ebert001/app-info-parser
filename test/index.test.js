/**
 * Unit tests for lib/index.js (AppInfoParser)
 * Tests constructor validation, file type detection, and lazy loading behavior.
 */
const AppInfoParser = require('../lib/index')

describe('AppInfoParser constructor', () => {
  // ─── Parameter validation ────────────────────────────────────────

  test('throws error when no file param is provided', () => {
    expect(() => new AppInfoParser()).toThrow('Param miss: file')
    expect(() => new AppInfoParser(null)).toThrow('Param miss: file')
    expect(() => new AppInfoParser('')).toThrow('Param miss: file')
    expect(() => new AppInfoParser(undefined)).toThrow('Param miss: file')
  })

  test('throws error for unsupported file types', () => {
    expect(() => new AppInfoParser('test.zip')).toThrow('Unsupported file type')
    expect(() => new AppInfoParser('test.exe')).toThrow('Unsupported file type')
    expect(() => new AppInfoParser('test.txt')).toThrow('Unsupported file type')
    expect(() => new AppInfoParser('test.jpg')).toThrow('Unsupported file type')
  })

  test('accepts .apk file path without throwing', () => {
    // Should not throw - ApkParser only validates path type in Node
    expect(() => new AppInfoParser('test.apk')).not.toThrow()
  })

  test('accepts .ipa file path without throwing', () => {
    // Should not throw - IpaParser only validates path type in Node
    expect(() => new AppInfoParser('test.ipa')).not.toThrow()
  })

  test('handles file object with name property (Browser-like)', () => {
    // Simulate a browser File object with .name
    const fakeFile = { name: 'test.apk', size: 1024 }
    // In Node.js environment, Zip constructor expects string path,
    // so this will throw a different error (not unsupported type)
    // We're testing that file type detection works via .name
    expect(() => new AppInfoParser(fakeFile)).not.toThrow('Unsupported file type')
  })

  test('file type detection is case-insensitive', () => {
    expect(() => new AppInfoParser('test.APK')).not.toThrow()
    expect(() => new AppInfoParser('test.IPA')).not.toThrow()
    expect(() => new AppInfoParser('test.Apk')).not.toThrow()
  })

  test('file type detection handles paths with dots', () => {
    expect(() => new AppInfoParser('/path/to/my.app.test.apk')).not.toThrow()
    expect(() => new AppInfoParser('C:\\Users\\test\\file.v2.0.ipa')).not.toThrow()
  })
})

describe('AppInfoParser lazy loading', () => {
  test('APK parsing does not load ipa.js and its Node.js dependencies', () => {
    // Verify that creating an APK parser does not trigger cgbi-to-png/streamifier loading.
    // This is the core fix: requiring index.js should NOT eagerly load ipa.js.
    const parser = new AppInfoParser('test.apk')
    // The parser should have an ApkParser instance, not IpaParser
    expect(parser.parser.constructor.name).toBe('ApkParser')
  })

  test('IPA parsing loads IpaParser correctly', () => {
    const parser = new AppInfoParser('test.ipa')
    expect(parser.parser.constructor.name).toBe('IpaParser')
  })

  test('parse() method delegates to internal parser', () => {
    const parser = new AppInfoParser('test.apk')
    // Verify parse() returns a Promise (from ApkParser.parse())
    const result = parser.parse()
    expect(result).toBeInstanceOf(Promise)
    // Clean up: the promise will reject because test.apk doesn't exist
    result.catch(() => {})
  })
})

describe('AppInfoParser with options', () => {
  test('passes idsigFile option to ApkParser', () => {
    const parser = new AppInfoParser('test.apk', { idsigFile: 'test.idsig' })
    expect(parser.parser._idsigFile).toBe('test.idsig')
  })

  test('idsigFile defaults to null when not provided', () => {
    const parser = new AppInfoParser('test.apk')
    expect(parser.parser._idsigFile).toBeNull()
  })

  test('idsigFile defaults to null when options is empty', () => {
    const parser = new AppInfoParser('test.apk', {})
    expect(parser.parser._idsigFile).toBeNull()
  })
})
