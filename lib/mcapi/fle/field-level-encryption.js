const LegacyCrypto = require('../crypto/legacy-crypto');
const JweCrypto = require('../crypto/jwe-crypto');
const utils = require('../utils/utils');

/**
 * @class
 * Performs field level encryption on HTTP payloads.
 *
 * @module fle/FieldLevelEncryption
 * @version 1.0.0
 */
function FieldLevelEncryption(config) {
  this.encrypt = encrypt;
  this.decrypt = decrypt;
  this.config = config;
  this.crypto = (config.mode === "JWE") ? new JweCrypto(config) : new LegacyCrypto(config);
  this.isWithHeader = Object.prototype.hasOwnProperty.call(config, "ivHeaderName") &&
    Object.prototype.hasOwnProperty.call(config, "encryptedKeyHeaderName");
  this.encryptionResponseProperties = [this.config.ivFieldName, this.config.encryptedKeyFieldName,
    this.config.publicKeyFingerprintFieldName, this.config.oaepHashingAlgorithmFieldName];
}

/**
 * @private
 */
function hasConfig(config, endpoint) {
  if (config && endpoint) {
    endpoint = endpoint.split("?").shift();
    const conf = config.paths.find((elem) => {
        const regex = new RegExp(elem.path, "g");
        return endpoint.match(regex);
      }
    );
    return (conf) ? conf : null;
  }
  return null;
}

/**
 * @private
 */
function elemFromPath(path, obj) {
  try {
    let parent = null;
    const paths = path.split(".");
    if (path && paths.length > 0) {
      paths.forEach((e) => {
          parent = obj;
          obj = isJsonRoot(e) ? obj : obj[e];
        }
      );
    }
    return {
      node: obj,
      parent: parent
    };
  } catch (e) {
    return null;
  }
}

/**
 * Set encryption header parameters
 *
 * @param header HTTP header
 * @param params Encryption parameters
 */
function setHeader(header, params) {
  header[this.config.encryptedKeyHeaderName] = params.encoded.encryptedKey;
  header[this.config.ivHeaderName] = params.encoded.iv;
  header[this.config.oaepHashingAlgorithmHeaderName] = params.oaepHashingAlgorithm.replace("-", "");
  header[this.config.publicKeyFingerprintHeaderName] = params.publicKeyFingerprint;
}


/**
 * Encrypt parts of a HTTP request using the given config
 *
 * @param endpoint HTTP URL for the current call
 * @param header HTTP Header
 * @param body HTTP Body
 * @returns {{header: *, body: *}}
 */
function encrypt(endpoint, header, body) {
  let bodyMap = body;
  const fleConfig = hasConfig(this.config, endpoint);
  if (fleConfig) {
    if (this.isWithHeader && fleConfig.mode !== "JWE") {
      const encParams = this.crypto.newEncryptionParams({});
      bodyMap = fleConfig.toEncrypt.map((v) => {
        return encryptWithHeader.call(this, encParams, v, body);
      });
      setHeader.call(this, header, encParams);
    } else {
      bodyMap = fleConfig.toEncrypt.map((v) => {
        return encryptBody.call(this, v, body);
      });
    }
  }
  return {
    header: header,
    body: fleConfig ? computeBody(fleConfig.toEncrypt, body, bodyMap) : body
  };
}

/**
 * Decrypt part of the HTTP response using the given config
 *
 * @public
 * @param response HTTP response to decrypt
 * @returns {*}
 */
function decrypt(response) {
  const body = response.body;
  let bodyMap = response.body;
  const fleConfig = hasConfig(this.config, response.request.url);
  if (fleConfig) {
    bodyMap = fleConfig.toDecrypt.map((v) => {
      if (this.isWithHeader && fleConfig.mode !== "JWE") {
        return decryptWithHeader.call(this, v, body, response);
      } else {
        return decryptBody.call(this, v, body);
      }
    });
  }
  return fleConfig ? computeBody(fleConfig.toDecrypt, body, bodyMap) : body;
}

/**
 * Encrypt body nodes with given path
 *
 * @private
 * @param path Config json path
 * @param body Body to encrypt
 */
function encryptBody(path, body) {
  const elem = elemFromPath(path.element, body);
  if (elem && elem.node) {
    const encryptedData = this.crypto.encryptData({data: elem.node});
    body = utils.mutateObjectProperty(path.obj,
      encryptedData,
      body);
    // delete encrypted field if not overridden
    if (!isJsonRoot(path.obj) && path.element !== path.obj + "." + this.config.encryptedValueFieldName) {
      utils.deleteNode(path.element, body);
    }
  }
  return body;
}

/**
 * Encrypt body nodes with given path, without setting crypto info in the body
 *
 * @private
 * @param encParams encoding params to use
 * @param path Config json path
 * @param body body to encrypt
 * @returns {Object} Encrypted body
 */
function encryptWithHeader(encParams, path, body) {
  const elem = elemFromPath(path.element, body).node;
  const encrypted = this.crypto.encryptData({data: elem}, encParams);
  const data = {[this.config.encryptedValueFieldName]: encrypted[this.config.encryptedValueFieldName]};
  return isJsonRoot(path.obj) ? data : {[path.obj]: data};
}

/**
 * Decrypt body nodes with given path
 *
 * @private
 * @param path Config json path
 * @param body encrypted body
 * @returns {Object} Decrypted body
 */
function decryptBody(path, body) {
  const elem = elemFromPath(path.element, body);
  if (elem && elem.node) {
    let decryptedObj = null;
    if (this.config.mode !== "JWE") {
      decryptedObj = this.crypto.decryptData(
        elem.node[this.config.encryptedValueFieldName], // encrypted data
        elem.node[this.config.ivFieldName], // iv field
        elem.node[this.config.oaepHashingAlgorithmFieldName], // oaepHashingAlgorithm
        elem.node[this.config.encryptedKeyFieldName] // encryptedKey
      );
    } else {
      decryptedObj = this.crypto.decryptData(elem.node[this.config.encryptedValueFieldName]);
    }
    return utils.mutateObjectProperty(path.obj, decryptedObj, body, path.element, this.encryptionResponseProperties);
  }
  return body;
}

/**
 * Decrypt body nodes with given path, getting crypto info from the header
 *
 * @private
 * @param path Config json path
 * @param body encrypted body
 * @param response Response with header to update
 */
function decryptWithHeader(path, body, response) {
  const elemEncryptedNode = elemFromPath(path.obj, body);
  const node = isJsonRoot(path.element) ? elemEncryptedNode.node : elemEncryptedNode.node[path.element];
  if (node) {
    const encryptedData = node[this.config.encryptedValueFieldName];
    for (const k in body) {
      // noinspection JSUnfilteredForInLoop
      delete body[k];
    }
    const decrypted = this.crypto.decryptData(
      encryptedData,
      response.header[this.config.ivHeaderName],
      response.header[this.config.oaepHashingAlgorithmHeaderName],
      response.header[this.config.encryptedKeyHeaderName]
    );
    return isJsonRoot(path.obj) ? decrypted : Object.assign(body, decrypted);
  }
}

function isJsonRoot(elem) {
  return elem === "$";
}

function computeBody(configParam, body, bodyMap){
  return (hasEncryptionParam(configParam, bodyMap)) ? bodyMap.pop() : body;
}

function hasEncryptionParam(encParams, bodyMap){
  return encParams && encParams.length === 1 && bodyMap && bodyMap[0];
}

module.exports = FieldLevelEncryption;
