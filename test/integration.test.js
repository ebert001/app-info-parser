/**
 * Integration tests for APK parsing.
 *
 * These tests require a real .apk file to be present at:
 *   test/fixtures/test.apk
 *
 * To add a test fixture:
 *   1. Copy any valid .apk file to test/fixtures/test.apk
 *   2. Run: npm test
 *
 * If no fixture is found, these tests are skipped automatically.
 */
const fs = require('fs')
const path = require('path')
const AppInfoParser = require('../lib/index')

const FIXTURE_DIR = path.join(__dirname, 'fixtures')
const APK_PATH = path.join(FIXTURE_DIR, 'test.apk')

const hasApkFixture = () => {
  try {
    return fs.existsSync(APK_PATH)
  } catch {
    return false
  }
}

const describeWithApk = hasApkFixture() ? describe : describe.skip

describeWithApk('APK Integration', () => {
  let parseResult

  beforeAll(async () => {
    const parser = new AppInfoParser(APK_PATH)
    parseResult = await parser.parse()
  })

  test('parses successfully and returns an object', () => {
    expect(parseResult).toBeDefined()
    expect(typeof parseResult).toBe('object')
  })

  // ─── Basic info fields ─────────────────────────────────────────

  test('extracts package name', () => {
    expect(parseResult.package).toBeDefined()
    expect(typeof parseResult.package).toBe('string')
    expect(parseResult.package.length).toBeGreaterThan(0)
  })

  test('extracts versionName', () => {
    // versionName may be null for some APKs, but the field should exist
    expect(parseResult).toHaveProperty('versionName')
  })

  test('extracts versionCode', () => {
    expect(parseResult).toHaveProperty('versionCode')
  })

  test('extracts minSdkVersion', () => {
    // minSdkVersion is nested inside usesSdk
    expect(parseResult).toHaveProperty('usesSdk')
    expect(parseResult.usesSdk).toHaveProperty('minSdkVersion')
  })

  // ─── Application info ──────────────────────────────────────────

  test('has application object', () => {
    expect(parseResult.application).toBeDefined()
    expect(typeof parseResult.application).toBe('object')
  })

  test('application has label or icon', () => {
    const app = parseResult.application
    // At least one of label/icon should be present
    const hasLabel = app.label && app.label.length > 0
    const hasIcon = app.icon && app.icon.length > 0
    expect(hasLabel || hasIcon).toBe(true)
  })

  // ─── Permissions ───────────────────────────────────────────────

  test('extracts permissions array', () => {
    expect(parseResult).toHaveProperty('usesPermissions')
    expect(Array.isArray(parseResult.usesPermissions)).toBe(true)
  })

  test('each permission has a name property', () => {
    if (parseResult.usesPermissions && parseResult.usesPermissions.length > 0) {
      parseResult.usesPermissions.forEach(perm => {
        // Permission can be a string or an object with name
        if (typeof perm === 'object') {
          expect(perm).toHaveProperty('name')
        }
      })
    }
  })

  // ─── Icon ──────────────────────────────────────────────────────

  test('extracts icon as base64 data URI or null', () => {
    if (parseResult.icon !== null) {
      expect(parseResult.icon).toMatch(/^data:image\/png;base64,/)
    }
  })

  // ─── Certificate / Signature ───────────────────────────────────

  test('has signature verification result', () => {
    expect(parseResult).toHaveProperty('signaturePass')
    expect(typeof parseResult.signaturePass).toBe('boolean')
  })

  test('has signature scheme info', () => {
    // signatureScheme should be a string like 'v1', 'v2/v3', etc. or null
    if (parseResult.signatureScheme !== null) {
      expect(typeof parseResult.signatureScheme).toBe('string')
      expect(parseResult.signatureScheme).toMatch(/^v[1-4]/)
    }
  })

  test('certChain is an array', () => {
    expect(parseResult).toHaveProperty('certChain')
    expect(Array.isArray(parseResult.certChain)).toBe(true)
  })

  test('each certificate has required fields', () => {
    if (parseResult.certChain && parseResult.certChain.length > 0) {
      parseResult.certChain.forEach(cert => {
        expect(cert).toHaveProperty('pem')
        expect(cert).toHaveProperty('subject')
        expect(cert).toHaveProperty('issuer')
        expect(cert).toHaveProperty('scheme')
      })
    }
  })

  test('at least one certificate exists for signed APK', () => {
    // Most real APKs are signed
    if (parseResult.signaturePass) {
      expect(parseResult.certChain.length).toBeGreaterThan(0)
    }
  })

  // ─── Activities / Components ───────────────────────────────────

  test('extracts activities if present', () => {
    if (parseResult.application.activity) {
      expect(Array.isArray(parseResult.application.activity)).toBe(true)
    }
  })

  test('extracts services if present', () => {
    if (parseResult.application.service) {
      expect(Array.isArray(parseResult.application.service)).toBe(true)
    }
  })
})

describe('APK Integration - error handling', () => {
  test('rejects with error for non-existent APK file', async () => {
    const parser = new AppInfoParser('/nonexistent/path/fake.apk')
    await expect(parser.parse()).rejects.toBeDefined()
  })
})
