const AppInfoParser = require('../src/index')
const IpaParser = require('../src/ipa')
const ApkParser = require('../src/apk')

// AppInfoParser parse apk
const apkInfoParser = new AppInfoParser('../packages/test.apk')
apkInfoParser.parse().then(result => {
  console.log('=== APK Basic Info ===')
  console.log('  package:', result.package)
  console.log('  versionName:', result.versionName)
  console.log('  versionCode:', result.versionCode)
  console.log('  icon base64:', result.icon ? result.icon.substring(0, 60) + '...' : 'null')

  console.log('\n=== Signature ===')
  console.log('  signaturePass:', result.signaturePass)
  console.log('  signatureScheme:', result.signatureScheme || 'unknown')
  console.log('  certError:', result.certError || 'none')

  console.log('\n=== Certificate Chain ===')
  if (result.certChain && result.certChain.length) {
    result.certChain.forEach((cert, i) => {
      console.log(`  [${i}] subject=${cert.subject} issuer=${cert.issuer}`)
      console.log(`      valid: ${cert.notBefore} ~ ${cert.notAfter}`)
      console.log(`      serial: ${cert.serialNumber} selfSigned: ${cert.isSelfSigned}`)
    })
  } else {
    console.log('  (no certificates)')
  }

  console.log('\n=== Permissions ===')
  if (result.usesPermissions && result.usesPermissions.length) {
    result.usesPermissions.forEach(p => console.log(' ', p.name || p))
  } else {
    console.log('  (none)')
  }
}).catch(e => {
  console.log('err ----> ', e)
})

// AppInfoParser parse ipa
const ipaInfoParser = new AppInfoParser('../packages/test.ipa')
ipaInfoParser.parse().then(result => {
  console.log('\n=== IPA Info ===')
  console.log('  info ---->', result)
  console.log('  icon base64 ---->', result.icon ? result.icon.substring(0, 60) + '...' : 'null')
}).catch(e => {
  console.log('err ----> ', e)
})

// IpaParser
const ipaParser = new IpaParser('../packages/test.ipa')
ipaParser.parse().then(result => {
  console.log('\n=== IPA (direct parser) ===')
  console.log('  info ---->', result)
  console.log('  icon base64 ---->', result.icon ? result.icon.substring(0, 60) + '...' : 'null')
}).catch(e => {
  console.log('err ----> ', e)
})

// ApkParser
const apkParser = new ApkParser('../packages/test.apk')
apkParser.parse().then(result => {
  console.log('\n=== APK (direct parser) ===')
  console.log('  package:', result.package)
  console.log('  versionName:', result.versionName)
  console.log('  signaturePass:', result.signaturePass)
  console.log('  certChain:', result.certChain ? result.certChain.length + ' certs' : 'none')
  console.log('  permissions:', result.usesPermissions ? result.usesPermissions.length + ' perms' : 'none')
  console.log('  icon base64:', result.icon ? result.icon.substring(0, 60) + '...' : 'null')
}).catch(e => {
  console.log('err ----> ', e)
})
