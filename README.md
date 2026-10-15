## apk-parser-js

[apk-parser-js](https://github.com/ebert001/app-info-parser) is an enhanced fork of [app-info-parser](https://github.com/chenquincy/app-info-parser), a parser for parsing `.ipa` or `.apk` files. It returns the information in JSON from `AndroidManifest.xml` or `Info.plist`.

**Enhanced features over the original:**

* Full APK signature verification (V1 / V2 / V3 / V4)
* X.509 certificate chain extraction from APK Signing Block
* PKCS#7 certificate parsing with `node-forge`

![](https://img.shields.io/npm/v/apk-parser-js.svg) ![](https://img.shields.io/npm/dt/apk-parser-js.svg) ![](https://img.shields.io/badge/language-javascript-yellow.svg)

## Support

* Node ✅

* Browser ✅（except IE）

* npx ✅

## Installation

``` shell
npm install apk-parser-js
# or yarn
yarn add apk-parser-js
```

## Getting started

### NPX Use

You can use apk-parser-js by npx, if you don't want to install it. Run this command in your terminal:

``` shell
npx apk-parser-js -f <file-path> -o <output-path>
```

| argument | type   | description                                                  |
| -------- | ------ | ------------------------------------------------------------ |
| -f       | string | The path of file that you want to parse.                     |
| -o       | string | The output path that you want to save the parse result. Default is "./result.json" |

### NPM Use

``` javascript
const AppInfoParser = require('apk-parser-js')
const parser = new AppInfoParser('../packages/test.apk') // or xxx.ipa
parser.parse().then(result => {
  console.log('app info ----> ', result)
  console.log('icon base64 ----> ', result.icon)
}).catch(err => {
  console.log('err ----> ', err)
})
```

### CDN Use

``` html
<input type="file" name="file" id="file" onchange="fileSelect()">
<script src="//unpkg.com/apk-parser-js/dist/app-info-parser.min.js"></script>
<script>
function fileSelect () {
  const files = document.getElementById('file').files
  const parser = new window.AppInfoParser(files[0])
  parser.parse().then(result => {
    console.log('app info ----> ', result)
    console.log('icon base64 ----> ', result.icon)
  }).catch(err => {
    console.log('err ----> ', err)
  })
}
</script>
```

### Demand loading

> You can use demand loading, when you only need one parser.

#### ApkParser

``` javascript
const ApkParser = require('apk-parser-js/src/apk')
const parser = new ApkParser('../packages/test.apk')
parser.parse().then(result => {
  console.log('app info ----> ', result)
  console.log('icon base64 ----> ', result.icon)
}).catch(err => {
  console.log('err ----> ', err)
})
```

#### IpaParser

``` javascript
const IpaParser = require('apk-parser-js/src/ipa')
const parser = new IpaParser('../packages/test.ipa')
parser.parse().then(result => {
  console.log('app info ----> ', result)
  console.log('icon base64 ----> ', result.icon)
}).catch(err => {
  console.log('err ----> ', err)
})
```

## API Reference

### AppInfoParser | ApkParser | IpaParser

* `constructor(file, options?)`
  * `file`   Blob or File in browser, Path in Node
  * `options` (optional, APK only)
    * `idsigFile` - Path | Blob | File of `.idsig` file for V4 signature verification
* `parse: () => Promise<Object>`   A function returning a promise, which resolves to the parse result

### Parse Result

| Field | Type | Description |
| --- | --- | --- |
| `package` | string | Package name (e.g. `com.example.app`) |
| `versionName` | string | Human-readable version string |
| `versionCode` | number | Numeric version code |
| `icon` | string | Base64-encoded app icon |
| `usesPermissions` | array | Declared permissions |
| `usesSdk` | object | `minSdkVersion`, `targetSdkVersion` |
| `certChain` | CertInfo[] | Extracted X.509 certificate chain |
| `signaturePass` | boolean | Whether signature verification passed |
| `signatureScheme` | string | Detected schemes (e.g. `v2/v3/v1`) |
| `certError` | string | Error message if cert parsing failed |

### CertInfo

| Field | Type | Description |
| --- | --- | --- |
| `pem` | string | Certificate in PEM format |
| `subject` | string | Full Distinguished Name (e.g. `C=CN, O=Org, CN=App`) |
| `issuer` | string | Full Distinguished Name of issuer |
| `notBefore` | string | Certificate validity start date (ISO 8601) |
| `notAfter` | string | Certificate validity end date (ISO 8601) |
| `serialNumber` | string | Certificate serial number |
| `isSelfSigned` | boolean | Whether subject equals issuer |
| `scheme` | string | Signature scheme: `v1`, `v2`, `v3`, or `v4` |

### Signature Verification

The parser supports all four APK signature schemes:

* **V1 (JAR signing):** Parses `META-INF/CERT.RSA` (PKCS#7), extracts certificate chain, verifies RSA signature and MANIFEST.MF digest.
* **V2 (APK Signing Block):** Locates the APK Signing Block between ZIP entries and Central Directory, extracts certificates from the V2 signature (`id=0x7109871a`).
* **V3 (APK Signing Block):** Same approach as V2 but for V3 signature (`id=0xf05368c0`), which supports key rotation.
* **V4 (.idsig file):** Parses the separate `.idsig` file (protobuf format) to extract certificates. Requires passing the `.idsig` file via `options.idsigFile`.

Certificates from ALL detected schemes are collected. Each certificate is tagged with its `scheme` field.

> **Note:** `signaturePass` indicates whether the signature is cryptographically valid. Certificate expiry does NOT affect `signaturePass`.

### V4 Signature Example

``` javascript
const AppInfoParser = require('apk-parser-js')
const parser = new AppInfoParser('app.apk', {
  idsigFile: 'app.apk.idsig'  // required for V4
})
parser.parse().then(result => {
  console.log('signature scheme:', result.signatureScheme) // e.g. "v4/v2/v3/v1"
  console.log('signature pass:', result.signaturePass)
  result.certChain.forEach(cert => {
    console.log(`[${cert.scheme}] ${cert.subject}`)
  })
}).catch(err => {
  console.log('err ----> ', err)
})
```

## License

MIT

## Resources

* [Changelog](https://github.com/ebert001/app-info-parser/blob/master/CHANGELOG.md)
* [Original project](https://github.com/chenquincy/app-info-parser)

## FAQ

### Build/Parse error with vite?

See this [issue](https://github.com/vitejs/vite/issues/2985) of vite, vite is not going support node global builtins and node specific api's on the client. Some of apk-parser-js's deps didn't support browser env, most of them without maintain, so it can't be resolved.

Just use apk-parser-js by CDN (import by script element), don't use it with module import in vite.
