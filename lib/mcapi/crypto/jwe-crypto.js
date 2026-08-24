const forge = require("node-forge");
const utils = require("../utils/utils");
const c = require("../utils/constants");
const nodeCrypto = require("crypto");

/**
 * @class JWE Crypto
 *
 * Constructor to create an instance of `JweCrypto`: provide JWE encrypt/decrypt methods
 *
 * @param config encryption/decryption service configuration
 * @constructor
 */
function JweCrypto(config) {
  isValidConfig.call(this, config);

  this.encryptionCertificate = readPublicCertificate(
    config.encryptionCertificate
  );

  this.privateKey = getPrivateKey(config);

  this.publicKeyFingerprint =
    config.publicKeyFingerprint ||
    computePublicFingerprint(config, this.encryptionCertificate);

  this.encryptedValueFieldName = config.encryptedValueFieldName;

  // Only parsed if this runtime needs the node-forge fallback, so callers on
  // node never pay for it. A config may also legitimately carry only one of
  // the two keys.
  let parsedPublicKey = null;
  let parsedPrivateKey = null;

  /**
   * Perform data encryption
   *
   * @public
   * @param options {Object} parameters
   * @param options.data {string} json string to encrypt
   */
  this.encryptData = function (options) {
    const data = utils.jsonToString(options.data);

    const jweHeader = {
      kid: this.publicKeyFingerprint,
      cty: "application/json",
      alg: "RSA-OAEP-256",
      enc: "A256GCM",
    };

    const encodedJweHeader = toEncodedString(
      JSON.stringify(jweHeader),
      c.UTF8,
      c.BASE64URL
    );

    const secretKey = nodeCrypto.randomBytes(32);
    const secretKeyBuffer = Buffer.from(secretKey, c.BINARY);

    let encryptedSecretKey;
    if (honoursOaepHash(this.encryptionCertificate)) {
      encryptedSecretKey = nodeCrypto.publicEncrypt(
        {
          key: this.encryptionCertificate,
          padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        secretKeyBuffer
      );
    } else {
      if (!parsedPublicKey) {
        parsedPublicKey = forge.pki.certificateFromPem(
          this.encryptionCertificate
        ).publicKey;
      }
      encryptedSecretKey = Buffer.from(
        parsedPublicKey.encrypt(
          secretKeyBuffer.toString(c.BINARY),
          "RSA-OAEP",
          createOAEPOptions()
        ),
        c.BINARY
      );
    }

    const iv = nodeCrypto.randomBytes(16);

    const cipher = nodeCrypto.createCipheriv("AES-256-GCM", secretKey, iv);
    cipher.setAAD(Buffer.from(encodedJweHeader, c.ASCII));
    let cipherText = cipher.update(data, c.UTF8, c.BASE64);
    cipherText += cipher.final(c.BASE64);
    const authTag = cipher.getAuthTag().toString(c.BASE64);

    const encodedEncryptedSecretKey = toEncodedString(
      encryptedSecretKey,
      c.BINARY,
      c.BASE64URL
    );
    const encodedIv = toEncodedString(iv, c.BINARY, c.BASE64URL);
    const encodedEncryptedText = toEncodedString(
      cipherText,
      c.BASE64,
      c.BASE64URL
    );
    const encodedAuthTag = toEncodedString(authTag, c.BASE64, c.BASE64URL);

    const encryptedData = serialize(
      encodedJweHeader,
      encodedEncryptedSecretKey,
      encodedIv,
      encodedEncryptedText,
      encodedAuthTag
    );
    return { [this.encryptedValueFieldName]: encryptedData };
  };

  /**
   * Perform data decryption
   *
   * @public
   * @param encryptedData encrypted data
   */
  this.decryptData = function (encryptedData) {
    if (!encryptedData || encryptedData.length <= 1) {
      throw new Error("Input not valid");
    }

    const jweTokenParts = deSerialize(encryptedData);
    const jweHeader = Buffer.from(jweTokenParts[0], c.BASE64).toString(c.UTF8);
    const encryptedSecretKey = Buffer.from(jweTokenParts[1], c.BASE64);
    const iv = Buffer.from(jweTokenParts[2], c.BASE64);
    const encryptedText = Buffer.from(jweTokenParts[3], c.BASE64);
    const authTag = Buffer.from(jweTokenParts[4], c.BASE64);

    let secretKey;
    if (honoursOaepHash(this.privateKey)) {
      secretKey = nodeCrypto.privateDecrypt(
        {
          key: this.privateKey,
          padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        Buffer.from(encryptedSecretKey, c.BINARY)
      );
    } else {
      if (!parsedPrivateKey) {
        parsedPrivateKey = forge.pki.privateKeyFromPem(this.privateKey);
      }
      secretKey = Buffer.from(
        parsedPrivateKey.decrypt(
          Buffer.from(encryptedSecretKey, c.BINARY).toString(c.BINARY),
          "RSA-OAEP",
          createOAEPOptions()
        ),
        c.BINARY
      );
    }

    let decryptionEncoding = JSON.parse(jweHeader).enc;
    let gcmMode = true;
    switch (decryptionEncoding) {
      case "A128GCM":
        decryptionEncoding = "AES-128-GCM";
        break;
      case "A192GCM":
        decryptionEncoding = "AES-192-GCM";
        break;
      case "A256GCM":
        decryptionEncoding = "AES-256-GCM";
        break;
      case "A128CBC-HS256":
        decryptionEncoding = "AES-128-CBC";
        secretKey = secretKey.slice(16, 32);
        gcmMode = false;
        break;
      default:
        throw new Error(
          "Unsupported decryption encoding: " + decryptionEncoding
        );
    }

    const authTagBinary = Buffer.from(authTag, c.BASE64);
    const decipher = nodeCrypto.createDecipheriv(
      decryptionEncoding,
      secretKey,
      Buffer.from(iv, c.BINARY),
      { authTagLength: authTagBinary.length }
    );
    if (gcmMode === true) {
      decipher.setAAD(Buffer.from(jweTokenParts[0], c.ASCII));
      decipher.setAuthTag(authTagBinary);
    }
    let data = decipher.update(encryptedText, c.BASE64, c.UTF8);
    data += decipher.final(c.UTF8);

    return utils.stringToJson(data);
  };
}

function serialize(header, encryptedSecretKey, iv, encryptedText, authTag) {
  return (
    header +
    "." +
    encryptedSecretKey +
    "." +
    iv +
    "." +
    encryptedText +
    "." +
    authTag
  );
}

function deSerialize(jweToken) {
  return jweToken.split(".");
}

/**
 * @private
 */
function readPublicCertificate(publicCertificatePath) {
  const publicCertificate = utils.readPublicCertificate(publicCertificatePath);
  if (publicCertificate) {
    return forge.pki.certificateToPem(publicCertificate);
  } else {
    return null;
  }
}

/**
 * @private
 */
function getPrivateKey(config) {
  const privateKey = utils.getPrivateKey(config);
  if (privateKey) {
    return forge.pki.privateKeyToPem(privateKey);
  } else {
    return null;
  }
}

/**
 * @private
 * @param config Configuration object
 */
function computePublicFingerprint(config, encryptionCertificate) {
  if (config && encryptionCertificate) {
    if(config.publicKeyFingerprintType) {
      return utils.computePublicFingerprint(
        config,
        forge.pki.certificateFromPem(encryptionCertificate),
        config.dataEncoding
      );
    } else {
      return utils.publicKeyFingerprint(
        forge.pki.certificateFromPem(encryptionCertificate)
      );
    }
  } else {
    return null;
  }
}

/**
 * Check if the passed configuration is valid
 * @throws {Error} if the config is not valid
 * @private
 */
function isValidConfig(config) {
  if (!utils.nodeVersionSupportsJWE()) {
    throw Error("JWE Encryption is only supported on Node 13+");
  }
  const propertiesBasic = ["encryptionCertificate", "encryptedValueFieldName"];
  const contains = utils.checkConfigFieldsArePopulated(config, propertiesBasic);
  utils.validateRootMapping(config);
  validateFingerprint(config, contains);
}

/**
 * @private
 */
function validateFingerprint(config, contains) {
  const propertiesFingerprint = ["publicKeyFingerprintType"];
  const propertiesOptionalDataEncoding = ["dataEncoding"];
  const propertiesOptionalFingerprint = ["publicKeyFingerprint"];
  if (
    contains(propertiesFingerprint) &&
    config[propertiesFingerprint[0]] !== "certificate" &&
    config[propertiesFingerprint[0]] !== "publicKey"
  ) {
    throw Error(
      "Config not valid: publicKeyFingerprintType should be: 'certificate' or 'publicKey'"
    );
  }
  if (
    !contains(propertiesOptionalFingerprint) &&
    config[propertiesFingerprint[0]] === "certificate" &&
    !(config[propertiesOptionalDataEncoding[0]] === c.BASE64 ||
    config[propertiesOptionalDataEncoding[0]] === c.HEX)
  ) {
    throw Error(
      "Config not valid: if publicKeyFingerprintType is 'certificate' dataEncoding must be either 'base64' or 'hex'"
    );
  }
}

/**
 * Does this runtime's crypto honour the `oaepHash` option?
 *
 * node validates the digest name and throws on an unrecognised one. The
 * crypto-browserify polyfill ignores `oaepHash` altogether and hard-codes
 * SHA-1, so it accepts a nonsense value without complaint. Attempting a wrap
 * under a bogus digest is therefore a cheap and side-effect free probe.
 *
 * This matters because a polyfilled `publicEncrypt` reports no error while
 * producing a token whose header advertises RSA-OAEP-256 over a key that was
 * actually wrapped with SHA-1. The failure only surfaces at the recipient.
 *
 * Memoised: the answer is a property of the bundle, not of the key.
 *
 * @private
 */
let nativeOaepHash = null;
function honoursOaepHash(keyPem) {
  if (nativeOaepHash !== null) {
    return nativeOaepHash;
  }
  if (
    typeof nodeCrypto.publicEncrypt !== "function" ||
    !nodeCrypto.constants ||
    !keyPem
  ) {
    // `resolve.fallback.crypto = false`, as set in this repo's webpack config,
    // leaves an empty module behind. Treat anything unusable as unsupported.
    nativeOaepHash = false;
    return nativeOaepHash;
  }
  try {
    nodeCrypto.publicEncrypt(
      {
        key: keyPem,
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "mcapi-oaep-support-probe",
      },
      Buffer.alloc(1)
    );
    nativeOaepHash = false;
  } catch {
    nativeOaepHash = true;
  }
  return nativeOaepHash;
}

/**
 * Build node-forge OAEP options for RSA-OAEP-256.
 *
 * The JWE header emitted by this module is always `"alg": "RSA-OAEP-256"`, so
 * the label digest and the MGF1 digest are both SHA-256. MGF1 has to be set
 * explicitly: node-forge defaults it to SHA-1, which yields a key wrap that no
 * conforming RSA-OAEP-256 implementation can undo.
 *
 * Mirrors createOAEPOptions in field-level-crypto.js.
 *
 * @private
 */
function createOAEPOptions() {
  const md = forge.md.sha256.create();
  return {
    md: md,
    mgf1: {
      md: md,
    },
  };
}

/**
 * @private
 */
function toEncodedString(value, fromFormat, toFormat) {
  let result = Buffer.from(value, fromFormat);
  if (toFormat === c.BASE64URL) {
    result = result.toString(c.BASE64);
    result = result.replace(/\+/g, "-");
    result = result.replace(/\\/g, "_");
    return result.replace(/=/g, "");
  } else {
    return result.toString(toFormat);
  }
}

module.exports = JweCrypto;
