/**
 * Unit tests for lib/utils.js
 */
const {
  isArray,
  isObject,
  isPrimitive,
  isBrowser,
  mapInfoResource,
  findApkIconPath,
  findIpaIconPath,
  getBase64FromBuffer,
  decodeNullUnicode
} = require('../lib/utils')

// ─── Type check utilities ────────────────────────────────────────────

describe('isArray', () => {
  test('returns true for arrays', () => {
    expect(isArray([])).toBe(true)
    expect(isArray([1, 2, 3])).toBe(true)
    expect(isArray(new Array(3))).toBe(true)
  })

  test('returns false for non-arrays', () => {
    expect(isArray({})).toBe(false)
    expect(isArray('string')).toBe(false)
    expect(isArray(123)).toBe(false)
    expect(isArray(null)).toBe(false)
    expect(isArray(undefined)).toBe(false)
  })
})

describe('isObject', () => {
  test('returns true for plain objects', () => {
    expect(isObject({})).toBe(true)
    expect(isObject({ a: 1 })).toBe(true)
  })

  test('returns false for non-objects', () => {
    expect(isObject([])).toBe(false)
    expect(isObject('string')).toBe(false)
    expect(isObject(123)).toBe(false)
    expect(isObject(null)).toBe(false)
  })
})

describe('isPrimitive', () => {
  test('returns true for primitive values', () => {
    expect(isPrimitive(null)).toBe(true)
    expect(isPrimitive(true)).toBe(true)
    expect(isPrimitive(false)).toBe(true)
    expect(isPrimitive(42)).toBe(true)
    expect(isPrimitive('hello')).toBe(true)
    expect(isPrimitive(undefined)).toBe(true)
  })

  test('returns false for non-primitive values', () => {
    expect(isPrimitive({})).toBe(false)
    expect(isPrimitive([])).toBe(false)
    expect(isPrimitive(() => {})).toBe(false)
  })
})

// ─── isBrowser ───────────────────────────────────────────────────────

describe('isBrowser', () => {
  test('returns false in Node.js environment', () => {
    // In Node.js, process is defined and is a process object
    expect(isBrowser()).toBe(false)
  })
})

// ─── decodeNullUnicode ───────────────────────────────────────────────

describe('decodeNullUnicode', () => {
  test('removes null unicode characters', () => {
    expect(decodeNullUnicode('hel\u0000lo')).toBe('hello')
    expect(decodeNullUnicode('\u0000test\u0000')).toBe('test')
  })

  test('returns string unchanged if no null characters', () => {
    expect(decodeNullUnicode('hello')).toBe('hello')
    expect(decodeNullUnicode('')).toBe('')
  })

  test('handles non-string input gracefully', () => {
    expect(decodeNullUnicode(null)).toBe(null)
    expect(decodeNullUnicode(undefined)).toBe(undefined)
    expect(decodeNullUnicode(123)).toBe(123)
  })
})

// ─── getBase64FromBuffer ─────────────────────────────────────────────

describe('getBase64FromBuffer', () => {
  test('converts buffer to base64 data URI', () => {
    const buf = Buffer.from('hello')
    const result = getBase64FromBuffer(buf)
    expect(result).toBe('data:image/png;base64,' + buf.toString('base64'))
  })

  test('handles empty buffer', () => {
    const buf = Buffer.from('')
    const result = getBase64FromBuffer(buf)
    expect(result).toBe('data:image/png;base64,')
  })

  test('handles binary buffer', () => {
    const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47]) // PNG header
    const result = getBase64FromBuffer(buf)
    expect(result).toMatch(/^data:image\/png;base64,/)
    expect(result.length).toBeGreaterThan(0)
  })
})

// ─── mapInfoResource ─────────────────────────────────────────────────

describe('mapInfoResource', () => {
  test('replaces resourceId strings with mapped values', () => {
    const apkInfo = {
      label: 'resourceId:0x7f010000',
      versionName: 'resourceId:0x7f010001'
    }
    const resourceMap = {
      '@7F010000': 'MyApp',
      '@7F010001': '1.0.0'
    }
    const result = mapInfoResource(apkInfo, resourceMap)
    expect(result.label).toBe('MyApp')
    expect(result.versionName).toBe('1.0.0')
  })

  test('handles nested objects', () => {
    const apkInfo = {
      application: {
        label: 'resourceId:0x7f010000'
      }
    }
    const resourceMap = { '@7F010000': 'NestedApp' }
    const result = mapInfoResource(apkInfo, resourceMap)
    expect(result.application.label).toBe('NestedApp')
  })

  test('handles arrays', () => {
    const apkInfo = {
      permissions: [
        { name: 'resourceId:0x7f010000' },
        { name: 'resourceId:0x7f010001' }
      ]
    }
    const resourceMap = {
      '@7F010000': 'READ_CONTACTS',
      '@7F010001': 'WRITE_CONTACTS'
    }
    const result = mapInfoResource(apkInfo, resourceMap)
    expect(result.permissions[0].name).toBe('READ_CONTACTS')
    expect(result.permissions[1].name).toBe('WRITE_CONTACTS')
  })

  test('leaves non-resourceId values unchanged', () => {
    const apkInfo = { label: 'DirectLabel', version: '1.0' }
    const resourceMap = { '@7F010000': 'Mapped' }
    const result = mapInfoResource(apkInfo, resourceMap)
    expect(result.label).toBe('DirectLabel')
    expect(result.version).toBe('1.0')
  })

  test('handles unmapped resourceId gracefully', () => {
    const apkInfo = { label: 'resourceId:0x7f010000' }
    const resourceMap = {} // empty map
    const result = mapInfoResource(apkInfo, resourceMap)
    expect(result.label).toBeUndefined()
  })

  test('does not modify empty strings or falsy values', () => {
    const apkInfo = { label: '', icon: null }
    const resourceMap = {}
    const result = mapInfoResource(apkInfo, resourceMap)
    expect(result.label).toBe('')
    expect(result.icon).toBe(null)
  })
})

// ─── findApkIconPath ─────────────────────────────────────────────────

describe('findApkIconPath', () => {
  test('returns highest density icon path', () => {
    const info = {
      application: {
        icon: [
          'res/mipmap-mdpi/ic_launcher.png',
          'res/mipmap-hdpi/ic_launcher.png',
          'res/mipmap-xhdpi/ic_launcher.png',
          'res/mipmap-xxhdpi/ic_launcher.png'
        ]
      }
    }
    const result = findApkIconPath(info)
    expect(result).toBe('res/mipmap-xxhdpi/ic_launcher.png')
  })

  test('returns first icon when no density matches', () => {
    const info = {
      application: {
        icon: ['res/icon.png']
      }
    }
    const result = findApkIconPath(info)
    expect(result).toBe('res/icon.png')
  })

  test('returns empty string when no icons', () => {
    const info = { application: { icon: null } }
    expect(findApkIconPath(info)).toBe('')

    const info2 = { application: {} }
    expect(findApkIconPath(info2)).toBe('')
  })

  test('returns empty string when icon array is empty', () => {
    const info = { application: { icon: [] } }
    expect(findApkIconPath(info)).toBe('')
  })

  test('selects xxxhdpi over lower densities', () => {
    const info = {
      application: {
        icon: [
          'res/mipmap-mdpi/ic.png',
          'res/mipmap-xxxhdpi/ic.png'
        ]
      }
    }
    const result = findApkIconPath(info)
    expect(result).toBe('res/mipmap-xxxhdpi/ic.png')
  })
})

// ─── findIpaIconPath ─────────────────────────────────────────────────

describe('findIpaIconPath', () => {
  test('returns icon path from CFBundleIconFiles', () => {
    const info = {
      CFBundleIcons: {
        CFBundlePrimaryIcon: {
          CFBundleIconFiles: ['AppIcon60x60', 'AppIcon76x76']
        }
      }
    }
    const result = findIpaIconPath(info)
    // Should return the last element
    expect(result).toBe('AppIcon76x76')
  })

  test('falls back to CFBundleIconFiles array', () => {
    const info = {
      CFBundleIconFiles: ['Icon-Small', 'Icon-40']
    }
    const result = findIpaIconPath(info)
    expect(result).toBe('Icon-40')
  })

  test('returns default path when no icon info', () => {
    const info = {}
    const result = findIpaIconPath(info)
    expect(result).toBe('.app/Icon.png')
  })

  test('returns default when CFBundleIconFiles is empty', () => {
    const info = {
      CFBundleIcons: {
        CFBundlePrimaryIcon: {
          CFBundleIconFiles: []
        }
      }
    }
    // Empty array falls through to default
    const result = findIpaIconPath(info)
    expect(result).toBe('.app/Icon.png')
  })
})
