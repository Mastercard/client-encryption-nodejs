const JweCrypto = require("../crypto/jwe-crypto");
const utils = require("../utils/utils");

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
 * Encrypt parts of a HTTP request using the given config
 *
 * @param endpoint HTTP URL for the current call
 * @param header HTTP Header
 * @param body HTTP Body
 * @returns {{header: *, body: *}}
 */
function encrypt(endpoint, header, body) {
  let bodyMap = body;
  const fleConfig = utils.hasConfig(this.config, endpoint);
  if (fleConfig) {
    bodyMap = fleConfig.toEncrypt.map((v) => {
      return encryptBody.call(this, v, body);
    });
  }
  return {
    header: header,
    body: fleConfig ? utils.computeBody(fleConfig.toEncrypt, body, bodyMap) : body,
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
  const fleConfig = utils.hasConfig(this.config, response.request.url);
  if (fleConfig) {
    bodyMap = fleConfig.toDecrypt.map((v) => {
      return decryptBody.call(this, v, body);
    });
  }
  return fleConfig ? utils.computeBody(fleConfig.toDecrypt, body, bodyMap) : body;
}

/**
 * Encrypt body nodes with given path
 *
 * @private
 * @param path Config json path
 * @param body Body to encrypt
 */
function encryptBody(path, body) {
  const elem = utils.elemFromPath(path.element, body);
  if (elem && elem.node) {
    const encryptedData = this.crypto.encryptData({ data: elem.node });
    body = utils.addEncryptedDataToBody(encryptedData, path, this.config.encryptedValueFieldName, body);
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
  const elem = utils.elemFromPath(path.element, body);
  if (elem && elem.node) {
    const encryptedValue = (path.element === this.config.encryptedValueFieldName) ?
      elem.node : elem.node instanceof Object ? elem.node[this.config.encryptedValueFieldName] : elem.node;
    const decryptedObj = this.crypto.decryptData(encryptedValue);
    return utils.mutateObjectProperty(
      path.obj,
      decryptedObj,
      body,
      path.element,
      []
    );
  }
  return body;
}

module.exports = JweEncryption;
