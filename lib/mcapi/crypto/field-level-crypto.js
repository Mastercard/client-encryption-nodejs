const forge = require("node-forge");
const utils = require("../utils/utils");
const c = require("../utils/constants");

/**
 * @class Field Level Crypto
 *
 * Constructor to create an instance of `FieldLevelCrypto`: provide encrypt/decrypt methods
 *
 * @param config encryption/decryption service configuration
 * @constructor
 */
function FieldLevelCrypto(config) {
  isValidConfig.call(this, config);

  // Load public certificate (for encryption)
  this.encryptionCertificate = utils.readPublicCertificate(
    config.encryptionCertificate
  );

  // Load private key (for decryption)
  this.privateKey = utils.getPrivateKey(config);

  this.encoding = config.dataEncoding;

  this.publicKeyFingerprint =
    config.publicKeyFingerprint ||
    utils.computePublicFingerprint(
      config,
      this.encryptionCertificate,
      this.encoding
    );

  this.publicKeyFingerprintFieldName = config.publicKeyFingerprintFieldName;

  this.oaepHashingAlgorithm = config.oaepPaddingDigestAlgorithm;

  this.encryptedValueFieldName = config.encryptedValueFieldName;

  this.encryptedKeyFieldName = config.encryptedKeyFieldName;

  this.oaepHashingAlgorithmFieldName = config.oaepHashingAlgorithmFieldName;

  /**
   * Perform data encryption
   *
   * @public
   * @param options {Object} parameters
   * @param options.data {string} json string to encrypt
   * @param options.iv (optional) byte string IV to use or generate a random one
   * @param options.secretKey (optional) byte string secretKey to use or generate a random one
   * @param encryptionParams encryption parameters
   */
  this.encryptData = function (options, encryptionParams) {
    const data = utils.jsonToString(options.data);

    // Generate encryption params
    const enc = encryptionParams || this.newEncryptionParams(options);

    // Create Cipher
    const cipher = forge.cipher.createCipher("AES-CBC", enc.secretKey);

    // Encrypt payload
    cipher.start({ iv: enc.iv });
    cipher.update(forge.util.createBuffer(data, c.UTF8));
    cipher.finish();
    const encrypted = cipher.output.getBytes();

    const encryptedData = {
      [this.encryptedValueFieldName]: utils.bytesToString(
        encrypted,
        this.encoding
      ),
      iv: utils.bytesToString(enc.iv, this.encoding),
      [this.encryptedKeyFieldName]: utils.bytesToString(
        enc.encryptedKey,
        this.encoding
      ),
    };
    if (this.publicKeyFingerprint) {
      encryptedData[this.publicKeyFingerprintFieldName] =
        this.publicKeyFingerprint;
    }
    if (this.oaepHashingAlgorithmFieldName) {
      encryptedData[this.oaepHashingAlgorithmFieldName] =
        this.oaepHashingAlgorithm.replace("-", "");
    }
    return encryptedData;
  };

  /**
   * Perform data decryption
   *
   * @public
   * @param encryptedData encrypted data
   * @param iv Initialization vector to use to create the Decipher
   * @param oaepHashingAlgorithm OAEP Algorithm to use
   * @param encryptedKey Encrypted key
   * @returns {Object} Decrypted Json object
   */
  this.decryptData = function (
    encryptedData,
    iv,
    oaepHashingAlgorithm,
    encryptedKey
  ) {
    const decryptedKey = this.privateKey.decrypt(
      utils.stringToBytes(encryptedKey, this.encoding),
      "RSA-OAEP",
      createOAEPOptions("RSA-OAEP", oaepHashingAlgorithm)
    );

    // Init decipher
    const decipher = forge.cipher.createDecipher("AES-CBC", decryptedKey);

    // Decrypt payload
    decipher.start({ iv: utils.stringToBytes(iv, this.encoding) });
    decipher.update(
      forge.util.createBuffer(
        utils.stringToBytes(encryptedData, this.encoding),
        c.BINARY
      )
    );
    decipher.finish();

    try {
      return JSON.parse(decipher.output.data);
    } catch (e) {
      return decipher.output.data;
    }
  };

  /**
   * Generate encryption parameters.
   * @public
   * @param options.iv IV to use instead to use a random IV
   * @param options.secretKey Secret Key to use instead to generate a random key
   * @returns {{secretKey: *, encryptedKey: *, iv: *}}
   */
  this.newEncryptionParams = function (options) {
    options = options || {};
    // Generate a random initialization vector (IV)
    const iv = options["iv"] || forge.random.getBytesSync(16);

    // Generate a secret key (should be 128 (or 256) bits)
    const secretKey =
      options["secretKey"] || generateSecretKey("AES", 128, "SHA-256");

    // Encrypt secret key with issuer key
    const encryptedKey = this.encryptionCertificate.publicKey.encrypt(
      secretKey,
      "RSA-OAEP",
      createOAEPOptions("RSA-OAEP", this.oaepHashingAlgorithm)
    );

    return {
      iv: iv,
      secretKey: secretKey,
      encryptedKey: encryptedKey,
      oaepHashingAlgorithm: this.oaepHashingAlgorithm,
      publicKeyFingerprint: this.publicKeyFingerprint,
      encoded: {
        iv: utils.bytesToString(iv, this.encoding),
        secretKey: utils.bytesToString(secretKey, this.encoding),
        encryptedKey: utils.bytesToString(encryptedKey, this.encoding),
      },
    };
  };
}

/**
 * @private
 */
function createOAEPOptions(asymmetricCipher, oaepHashingAlgorithm) {
  if (asymmetricCipher.includes("OAEP") && oaepHashingAlgorithm !== null) {
    const mdForOaep = createMessageDigest(oaepHashingAlgorithm);
    return {
      md: mdForOaep,
      mgf1: {
        md: mdForOaep,
      },
    };
  }
}

/**
 * @private
 */
function createMessageDigest(digest) {
  switch (digest.toUpperCase()) {
    case "SHA-256":
    case "SHA256":
      return forge.md.sha256.create();
    case "SHA-512":
    case "SHA512":
      return forge.md.sha512.create();
  }
}

/**
 * @private
 */
function generateSecretKey(algorithm, size, digest) {
  if (algorithm === "AES") {
    const key = forge.random.getBytesSync(size / 8);
    const md = createMessageDigest(digest);
    md.update(key);
    return md.digest().getBytes(16);
  }
  throw new Error("Unsupported symmetric algorithm");
}

/**
 * Check if the passed configuration is valid
 * @throws {Error} if the config is not valid
 * @private
 */
function isValidConfig(config) {
  const propertiesBasic = [
    "oaepPaddingDigestAlgorithm",
    "dataEncoding",
    "encryptionCertificate",
    "encryptedValueFieldName",
  ];
  const propertiesField = ["ivFieldName", "encryptedKeyFieldName"];
  const propertiesHeader = [
    "ivHeaderName",
    "encryptedKeyHeaderName",
    "oaepHashingAlgorithmHeaderName",
  ];
  const contains = (props) => {
    return props.every((elem) => {
      return config[elem] !== null && typeof config[elem] !== "undefined";
    });
  };
  if (typeof config !== "object" || config === null) {
    throw Error("Config not valid: config should be an object.");
  }
  if (
    config["paths"] === null ||
    typeof config["paths"] === "undefined" ||
    !(config["paths"] instanceof Array)
  ) {
    throw Error("Config not valid: paths should be an array of path element.");
  }
  if (
    !contains(propertiesBasic) ||
    (!contains(propertiesField) && !contains(propertiesHeader))
  ) {
    throw Error(
      "Config not valid: please check that all the properties are defined."
    );
  }
  if (config["paths"].length === 0) {
    throw Error("Config not valid: paths should be not empty.");
  }
  if (config["dataEncoding"] !== c.HEX && config["dataEncoding"] !== c.BASE64) {
    throw Error("Config not valid: dataEncoding should be 'hex' or 'base64'");
  }
  validateFingerprint(config, contains);
  utils.validateRootMapping(config);
}

function validateFingerprint(config, contains) {
  const propertiesFingerprint = [
    "publicKeyFingerprintType",
    "publicKeyFingerprintFieldName",
    "publicKeyFingerprintHeaderName",
  ];
  const propertiesOptionalFingerprint = ["publicKeyFingerprint"];
  if (
    !contains(propertiesOptionalFingerprint) &&
    (config[propertiesFingerprint[1]] || config[propertiesFingerprint[2]]) &&
    config[propertiesFingerprint[0]] !== "certificate" &&
    config[propertiesFingerprint[0]] !== "publicKey"
  ) {
    throw Error(
      "Config not valid: propertiesFingerprint should be: 'certificate' or 'publicKey'"
    );
  }
}

module.exports = FieldLevelCrypto;
