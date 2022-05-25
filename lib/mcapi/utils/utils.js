const forge = require('node-forge');
const fs = require('fs');
const c = require("../utils/constants");

/**
 * Utils module
 * @Module Utils
 * @version 1.0.0
 */

module.exports.isSet = function (value) {
  return isSet(value);
};

 function isSet (value) {
  return typeof value !== "undefined" && value !== null && value.length !== 0;
};

/**
 * Converts a 'binary' encoded string of bytes to (hex or base64) encoded string.
 *
 * @param bytes Bytes to convert
 * @param dataEncoding encoding to use (hex or base64)
 * @returns {string} encoded string
 */
module.exports.bytesToString = function (bytes, dataEncoding) {
  return bytesToString(bytes, dataEncoding);
};

function bytesToString(bytes, dataEncoding) {
  if (typeof bytes === "undefined" || bytes === null) {
    throw new Error("Input not valid");
  }
  switch (dataEncoding.toLowerCase()) {
    case c.HEX:
      return forge.util.bytesToHex(bytes);
    case c.BASE64:
    default:
      return forge.util.encode64(bytes);
  }
}

/**
 * Converts a (hex or base64) string into a 'binary' encoded string of bytes.
 *
 * @param value string to convert
 * @param dataEncoding encoding to use (hex or base64)
 * @returns binary encoded string of bytes
 */
module.exports.stringToBytes = function (value, dataEncoding) {
  if (typeof value === "undefined" || value === null) {
    throw new Error("Input not valid");
  }
  switch (dataEncoding.toLowerCase()) {
    case c.HEX:
      return forge.util.hexToBytes(value);
    case c.BASE64:
    default:
      return forge.util.decode64(value);
  }
};

module.exports.toByteArray = function(value, fromFormat) {
  return Buffer.from(value, fromFormat);
};

/**
 * Convert a json object or json string to string
 *
 * @param {Object|string} data Json string or Json obj
 * @returns {string}
 */
module.exports.jsonToString = function (data) {
  if (typeof data === "undefined" || data === null) {
    throw new Error("Input not valid");
  }
  try {
    if (typeof data === 'string' || data instanceof String) {
      return JSON.stringify(JSON.parse(data));
    } else {
      return JSON.stringify(data);
    }
  } catch (e) {
    throw new Error("Json not valid");
  }
};

module.exports.mutateObjectProperty = function (path, value, obj, srcPath, properties) {
  let tmp = obj;
  let prev = null;
  if (path) {
    if (srcPath !== null && srcPath !== undefined) {
      this.deleteNode(srcPath, obj, properties); // delete src
    }
    const paths = path.split(".");
    paths.forEach((e) => {
      if (!Object.prototype.hasOwnProperty.call(tmp, e)) {
        tmp[e] = {};
      }
      prev = tmp;
      tmp = tmp[e];
    });
    const elem = path.split(".").pop();
    if (elem === "$"){
      obj = value; // replace root
    } else if (typeof value === 'object' && !(value instanceof Array)) { // decrypted value
      if (typeof prev[elem] !== 'object') {
        prev[elem] = {};
      }
      overrideProperties(prev[elem], value);
    } else {
      prev[elem] = value;
    }
  }
  return obj;
};

module.exports.deleteNode = function (path, obj, properties) {
  properties = properties || [];
  let prev = obj;
  if (path !== null && path !== undefined && obj !== null && obj !== undefined) {
    const paths = path.split('.');
    const toDelete = paths[paths.length - 1];
    paths.forEach((e, index) => {
      prev = obj;
      if (Object.prototype.hasOwnProperty.call(obj, e)) {
        obj = obj[e];
        if (obj && index === paths.length - 1) {
          delete prev[toDelete];
        }
      }
    });
    deleteRoot(obj, paths, properties);
  }
};

function overrideProperties(target, obj) {
  for (const k in obj) {
    target[k] = obj[k];
  }
}

function deleteRoot(obj, paths, properties){
  if (paths.length === 1) {
    properties = paths[0] === "$" ? Object.keys(obj) : properties;
    properties.forEach((e) => {
      delete obj[e];
    });
  }
}

module.exports.getPrivateKey = function(config){
  if (config.privateKey) {
    return loadPrivateKey(config.privateKey);
  } else if (config.keyStore) {
    if (config.keyStore.includes(".p12")) {
      return getPrivateKey12(config.keyStore, config.keyStoreAlias, config.keyStorePassword);
    }
    if (config.keyStore.includes(".pem")) {
      return getPrivateKeyPem(config.keyStore);
    }
    if (config.keyStore.includes(".der")) {
      return getPrivateKeyDer(config.keyStore);
    }
  }
  return null;
};

function getPrivateKey12(p12Path, alias, password) {
  const p12Content = fs.readFileSync(p12Path, 'binary');

  if (!p12Content || p12Content.length <= 1) {
    throw new Error('p12 keystore content is empty');
  }

  if (!isSet(alias)) {
    throw new Error('Key alias is not set');
  }

  if (!isSet(password)) {
    throw new Error('Keystore password is not set');
  }

  // Get asn1 from DER
  const p12Asn1 = forge.asn1.fromDer(p12Content, false);

  // Get p12 using the password
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

  // Get Key from p12
  const keyObj = p12.getBags({
    friendlyName: alias,
    bagType: forge.pki.oids.pkcs8ShroudedKeyBag
  }).friendlyName[0];

  if (!isSet(keyObj)) {
    throw new Error("No key found for alias [" + alias + "]");
  }

  return keyObj.key;
}

function getPrivateKeyPem(pemPath) {
  let pemContent = fs.readFileSync(pemPath, 'binary');

  if (!pemContent || pemContent.length <= 1) {
    throw new Error('pem keystore content is empty');
  }

  pemContent = pemContent.replace("\n", "");
  pemContent = pemContent.replace("\r\n", "");

  return forge.pki.privateKeyFromPem(pemContent);
}

function getPrivateKeyDer(derPath) {
  const derContent = fs.readFileSync(derPath, 'binary');

  if (!derContent || derContent.length <= 1) {
    throw new Error('der keystore content is empty');
  }

  const pkeyAsn1 = forge.asn1.fromDer(derContent);
  return forge.pki.privateKeyFromAsn1(pkeyAsn1);
}

function loadPrivateKey(privateKeyPath) {
  const privateKeyContent = fs.readFileSync(privateKeyPath, 'binary');

  if (!privateKeyContent || privateKeyContent.length <= 1) {
    throw new Error('Private key content not valid');
  }

  return forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(privateKeyContent));
}

module.exports.readPublicCertificate = function(publicCertificatePath){
  const certificateContent = fs.readFileSync(publicCertificatePath);
  if (!certificateContent || certificateContent.length <= 1) {
    throw new Error('Public certificate content is not valid');
  }
  return forge.pki.certificateFromPem(certificateContent);
};

module.exports.computePublicFingerprint = function(config, encryptionCertificate, encoding) {
  let fingerprint = null;
  if (config && config.publicKeyFingerprintType) {
    switch (config.publicKeyFingerprintType) {
      case "certificate":
        fingerprint = publicCertificateFingerprint(encryptionCertificate, encoding);
        break;
      case "publicKey":
        fingerprint = publicKeyFingerprint(encryptionCertificate);
        break;
    }
  }
  return fingerprint;
};

function publicCertificateFingerprint(publicCertificate, encoding) {
  const bytes = forge.asn1.toDer(forge.pki.certificateToAsn1(publicCertificate)).getBytes();
  const md = createMessageDigest('SHA-256');
  md.update(bytes);
  return bytesToString(md.digest().getBytes(), encoding);
}

function publicKeyFingerprint(publicCertificate) {
  return forge.pki.getPublicKeyFingerprint(publicCertificate.publicKey, {
    type: 'SubjectPublicKeyInfo',
    md: createMessageDigest('SHA-256'),
    encoding: c.HEX
  });
}

function createMessageDigest(digest) {
  switch (digest.toUpperCase()) {
    case 'SHA-256':
    case 'SHA256':
      return forge.md.sha256.create();
    case 'SHA-512':
    case 'SHA512':
      return forge.md.sha512.create();
  }
}

module.exports.nodeVersionSupportsJWE = function (){
  const nodeMajorVersion = parseInt(process.version.substring(1,3));
  return (nodeMajorVersion > 12);
};

