const JweCrypto = require('../crypto/jwe-crypto');
const utils = require('../utils/utils');

/**
 * @class
 * Performs JWE encryption on HTTP payloads.
 *
 * @module encryption/JweEncryption
 * @version 1.0.0
 */
function JweEncryption(config) {
  this.encrypt = encrypt;
  this.decrypt = decrypt;
  this.config = config;
  this.crypto = new JweCrypto(config);
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
    bodyMap = fleConfig.toEncrypt.map((v) => {
      return encryptBody.call(this, v, body);
    });
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
        return decryptBody.call(this, v, body);
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
    const decryptedObj = this.crypto.decryptData(elem.node[this.config.encryptedValueFieldName]);
    return utils.mutateObjectProperty(path.obj, decryptedObj, body, path.element, []);
  }
  return body;
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

module.exports = JweEncryption;
