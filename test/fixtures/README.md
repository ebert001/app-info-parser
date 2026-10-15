# Test Fixtures

Place test files here for integration tests.

## Required Files

- `test.apk` - A valid Android APK file for integration testing

## How to Add

```bash
# Copy any valid APK file here
cp /path/to/your/app.apk test/fixtures/test.apk
```

## Notes

- Integration tests are **automatically skipped** if `test.apk` is not present
- The test APK should be a real, signed APK for full coverage (certificate tests)
- Do NOT commit APK files to git - they are binary and can be large
- `test/fixtures/` is listed in `.gitignore`
