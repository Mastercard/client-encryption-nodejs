const forge = require('node-forge');
const fs = require('fs');
const utils = require('../utils/utils');
const nodeCrypto = require('crypto');

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

  this.encryptionCertificate = readPublicCertificate(config.encryptionCertificate);

  this.privateKey = getPrivateKey(config);

  this.publicKeyFingerprint = config.publicKeyFingerprint || computePublicFingerprint.call(this, config);

  this.encryptedValueFieldName = config.encryptedValueFieldName;

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
      "kid": this.publicKeyFingerprint,
      "cty": "application/json",
      "alg": "RSA-OAEP-256",
      "enc": "A256GCM"
    };

    const encodedJweHeader = Buffer.from(JSON.stringify(jweHeader)).toString('base64url');

    const secretKey = nodeCrypto.randomBytes(32);
    const secretKeyBuffer = Buffer.from(secretKey, 'binary');

    const encryptedSecretKey = nodeCrypto.publicEncrypt(
      {
        key: this.encryptionCertificate,
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      secretKeyBuffer
    );

    const iv = nodeCrypto.randomBytes(16);

    const cipher = nodeCrypto.createCipheriv("AES-256-GCM", secretKey, iv);
    cipher.setAAD(Buffer.from(encodedJweHeader, "ascii"));
    let cipherText = cipher.update(data, "utf8", 'base64');
    cipherText += cipher.final('base64');
    const authTag = cipher.getAuthTag().toString("base64");

    const encodedEncryptedSecretKey = Buffer.from(encryptedSecretKey, 'binary').toString('base64url');
    const encodedIv = Buffer.from(iv, 'binary').toString('base64url');
    const encodedEncryptedText = Buffer.from(cipherText, "base64").toString('base64url');
    const encodedAuthTag = Buffer.from(authTag, "base64").toString('base64url');

    const encryptedData = serialize(encodedJweHeader, encodedEncryptedSecretKey, encodedIv, encodedEncryptedText, encodedAuthTag);
    return { [this.encryptedValueFieldName] : encryptedData};
  };

  /**
   * Perform data decryption
   *
   * @public
   * @param encryptedData encrypted data
   */
  this.decryptData = function (encryptedData) {
    if (!encryptedData || encryptedData.length <= 1) {
      throw new Error('Input not valid');
    }

    const jweTokenParts = deSerialize(encryptedData);
    const jweHeader = Buffer.from(jweTokenParts[0], 'base64url').toString('utf8');
    const encryptedSecretKey = Buffer.from(jweTokenParts[1], 'base64url');
    const iv = Buffer.from(jweTokenParts[2], 'base64url');
    const encryptedText = Buffer.from(jweTokenParts[3], 'base64url');
    const authTag = Buffer.from(jweTokenParts[4], 'base64url');

    // const node10 = utils.isNode10()

    let secretKey = nodeCrypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(encryptedSecretKey, 'binary')
    );

    let decryptionEncoding = JSON.parse(jweHeader).enc;
    let gcmMode = true;
    switch (decryptionEncoding) {
      case "A256GCM":
        decryptionEncoding = "AES-256-GCM";
        break;
      case "A128GCM":
        decryptionEncoding = "AES-128-GCM";
        break;
      case "A128CBC-HS256":
        decryptionEncoding = "AES-128-CBC";
        secretKey = secretKey.slice(16, 32);
        gcmMode = false;
        break;
      default:
        throw new Error('Unsupported decryption encoding: ' + decryptionEncoding);
    }

    const authTagBinary = Buffer.from(authTag, "base64");
    const dcipher = nodeCrypto.createDecipheriv(decryptionEncoding, secretKey, Buffer.from(iv, 'binary'), {authTagLength: authTagBinary.length});
    if (gcmMode === true) {
      dcipher.setAAD(Buffer.from(jweTokenParts[0], "ascii"));
      dcipher.setAuthTag(authTagBinary);
    }
    let data = dcipher.update(encryptedText, "base64", "utf8");
    data += dcipher.final('utf8');

    return JSON.parse(data);
  };
}

function serialize(header, encryptedSecretKey, iv, encryptedText, authTag) {
  return header + '.' + encryptedSecretKey + '.' + iv + '.' + encryptedText + '.' + authTag;
}

function deSerialize(jweToken) {
  return jweToken.split(".");
}

/**
 * @private
 */
function readPublicCertificate(publicCertificatePath) {
  const certificateContent = fs.readFileSync(publicCertificatePath, 'binary');
  if (!certificateContent || certificateContent.length <= 1) {
    throw new Error('Public certificate content is not valid');
  }
  return certificateContent;
}

/**
 * @private
 */
function getPrivateKey(config) {
  const privateKey = utils.getPrivateKey(config);
  if( privateKey ){
    return forge.pki.privateKeyToPem(privateKey);
  }else{
    return null;
  }
}

/**
 * @private
 * @param config Configuration object
 */
function computePublicFingerprint(config) {
  let fingerprint = null;
  if (config && config.publicKeyFingerprintType) {
    switch (config.publicKeyFingerprintType) {
      case "certificate":
        fingerprint = publicCertificateFingerprint.call(this, this.encryptionCertificate);
        break;
      case "publicKey":
        fingerprint = publicKeyFingerprint.call(this, this.encryptionCertificate);
        break;
    }
  }
  return fingerprint;
}

/**
 * Get SHA-256 certificate fingerprint from a X509 certificate
 *
 * @private
 * @param {string} publicCertificate PEM
 */
function publicCertificateFingerprint(publicCertificate) {
  if (!publicCertificate || publicCertificate.length <= 1) {
    throw new Error('Public certificate content is not valid');
  }
  let hexFingerprint = new nodeCrypto.X509Certificate(publicCertificate).fingerprint256;
  hexFingerprint = hexFingerprint.replaceAll(":", "");
  return Buffer.from(hexFingerprint, 'hex').toString('base64');
}

/**
 * Get SHA-256 public Key fingerprint from a X509 certificate
 *
 * @private
 * @param {string} publicCertificate PEM
 */
function publicKeyFingerprint(publicKey) {
  if (!publicKey || publicKey.length <= 1) {
    throw new Error('Public certificate content is not valid');
  }
  let hexFingerprint = new nodeCrypto.X509Certificate(publicKey).fingerprint256;
  hexFingerprint = hexFingerprint.replaceAll(":", "");
  return Buffer.from(hexFingerprint, 'hex').toString('base64');
}


/**
 * Check if the passed configuration is valid
 * @throws {Error} if the config is not valid
 * @private
 */
function isValidConfig(config) {
  const propertiesBasic = ["encryptionCertificate", "encryptedValueFieldName"];
  const contains = (props) => {
    return props.every((elem) => {
      return config[elem] !== null && typeof config[elem] !== "undefined";
    });
  };
  if (typeof config !== 'object' || config === null) {
    throw Error("Config not valid: config should be an object.");
  }
  if (config["paths"] === null || typeof config["paths"] === "undefined" ||
    !(config["paths"] instanceof Array)) {
    throw Error("Config not valid: paths should be an array of path element.");
  }
  if (!contains(propertiesBasic)) {
    throw Error("Config not valid: please check that all the properties are defined.");
  }
  if (config["paths"].length === 0) {
    throw Error("Config not valid: paths should be not empty.");
  }
  validateFingerprint(config, contains);
  validateRootMapping(config);
}

/**
 * @private
 */
function validateFingerprint(config, contains) {
  const propertiesFingerprint = ["publicKeyFingerprintType"];
  const propertiesOptionalFingerprint = ["publicKeyFingerprint"];
  if (!contains(propertiesOptionalFingerprint)
    && config[propertiesFingerprint[0]] !== "certificate" && config[propertiesFingerprint[0]] !== "publicKey") {
    throw Error("Config not valid: propertiesFingerprint should be: 'certificate' or 'publicKey'");
  }
}

/**
 * @private
 */
function validateRootMapping(config) {
  function multipleRoots(elem) {
    return elem.length !== 1 && elem.some((item) => {
      return item.obj === "$" || item.element === "$";
    });
  }

  config.paths.forEach((path) => {
    if (multipleRoots(path.toEncrypt) || multipleRoots(path.toDecrypt)) {
      throw Error("Config not valid: found multiple configurations encrypt/decrypt with root mapping");
    }
  });
}

module.exports = JweCrypto;
