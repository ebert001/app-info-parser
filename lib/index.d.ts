
/**
 * AppInfoParser - Parse APK/IPA files to extract app information
 * 
 * @example
 * ```typescript
 * import AppInfoParser from 'app-info-parser';
 * 
 * const parser = new AppInfoParser('/path/to/app.apk');
 * const info = await parser.parse();
 * console.log(info.package, info.versionName);
 * ```
 */
declare class AppInfoParser {
    /**
     * Create a new parser instance
     * @param filePath - Path to the APK or IPA file
     * @param options - Optional parameters (e.g. idsigFile for V4 signature)
     */
    constructor(filePath: string, options?: AppInfoParser.ParserOptions);
}
    /**
     * Parse the APK/IPA file and extract app information
     * @returns Parsed app information containing package details
     * @throws {Error} If file cannot be parsed
     */
    parse(): Promise<AppInfoParser.AppInfo>;
}

declare namespace AppInfoParser {
    /**
     * Application information extracted from APK/IPA file
     */
    export interface AppInfo {
        /**
         * Package/Bundle identifier
         * @example "com.example.myapp"
         */
        package: string;

        /**
         * Numeric version code (Android) or build number (iOS)
         * @example 123
         */
        versionCode: number;

        /**
         * Human-readable version string
         * @example "1.2.3"
         */
        versionName: string;

        /**
         * Whether the APK signature is valid
         * true = signature verified, all certs valid
         * false = signature invalid or verification failed
         */
        signaturePass?: boolean;

        /**
         * Signature scheme used: 'v1' (JAR), 'v2' (APK Signing Block), 'v3' (APK Signing Block with key rotation), 'v4' (.idsig file)
         */
        signatureScheme?: 'v1' | 'v2' | 'v3' | 'v4' | null;

        /**
         * X.509 certificate chain extracted from META-INF/CERT.RSA (V1) or APK Signing Block (V2/V3)
         */
        certChain?: CertInfo[];

        /**
         * Error message if certificate parsing failed
         */
        certError?: string;

        /**
         * Application metadata and resources
         */
        application?: ApplicationInfo;

        /**
         * Platform-specific metadata
         * Additional fields vary by platform (APK vs IPA)
         */
        [key: string]: any;
    }

    /**
     * X.509 certificate information from APK signing certificate
     */
    export interface CertInfo {
        /**
         * Certificate in PEM format
         */
        pem: string;

        /**
         * Subject Common Name (CN) or Organization (O)
         */
        subject: string;

        /**
         * Issuer Common Name (CN) or Organization (O)
         */
        issuer: string;

        /**
         * Certificate validity start date (ISO 8601)
         */
        notBefore: string;

        /**
         * Certificate validity end date (ISO 8601)
         */
        notAfter: string;

        /**
         * Certificate serial number
         */
        serialNumber: string;

        /**
         * Whether this is a self-signed certificate
         */
        isSelfSigned: boolean;

        /**
         * Signature scheme this certificate belongs to: 'v1' (JAR), 'v2' (APK Signing Block), 'v3' (APK Signing Block with key rotation), 'v4' (.idsig file)
         */
        scheme?: 'v1' | 'v2' | 'v3' | 'v4';
    }

    /**
     * Application metadata from manifest
     */
    export interface ApplicationInfo {
        /**
         * App display name/label
         * Can contain multiple language variants
         * @example ["My App", "我的应用"]
         */
        label?: string[];

        /**
         * Path to app icon within package
         * @example "res/drawable/icon.png"
         */
        icon?: string;

        /**
         * Other manifest attributes
         */
        [key: string]: any;
    }

    /**
     * Parser options
     */
    export interface ParserOptions {
        /**
         * Path to .idsig file for V4 signature verification.
         * V4 signature is stored in a separate .idsig file alongside the APK.
         */
        idsigFile?: string | File | Blob;
    }
}

export = AppInfoParser;