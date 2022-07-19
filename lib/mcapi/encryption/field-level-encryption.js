const FieldLevelCrypto = require("../crypto/field-level-crypto");
const utils = require("../utils/utils");

/**
 * @class
 * Performs field level encryption on HTTP payloads.
 *
 * @module encryption/FieldLevelEncryption
 * @version 1.0.0
 */
function FieldLevelEncryption(config) {
  this.encrypt = encrypt;
  this.decrypt = decrypt;
  this.config = config;
  this.crypto = new FieldLevelCrypto(config);
  this.isWithHeader =
    Object.prototype.hasOwnProperty.call(config, "ivHeaderName") &&
    Object.prototype.hasOwnProperty.call(config, "encryptedKeyHeaderName");
  this.encryptionResponseProperties = [
    this.config.ivFieldName,
    this.config.encryptedKeyFieldName,
    this.config.publicKeyFingerprintFieldName,
    this.config.oaepHashingAlgorithmFieldName,
  ];
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
  header[this.config.oaepHashingAlgorithmHeaderName] =
    params.oaepHashingAlgorithm.replace("-", "");
  header[this.config.publicKeyFingerprintHeaderName] =
    params.publicKeyFingerprint;
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
    if (!this.isWithHeader) {
      bodyMap = fleConfig.toEncrypt.map((v) => {
        return encryptBody.call(this, v, body);
      });
    } else {
      const encParams = this.crypto.newEncryptionParams({});
      bodyMap = fleConfig.toEncrypt.map((v) => {
        return encryptWithHeader.call(this, encParams, v, body);
      });
      setHeader.call(this, header, encParams);
    }
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
      if (!this.isWithHeader) {
        return decryptBody.call(this, v, body);
      } else {
        return decryptWithHeader.call(this, v, body, response);
      }
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
 * Encrypt body nodes with given path, without setting crypto info in the body
 *
 * @private
 * @param encParams encoding params to use
 * @param path Config json path
 * @param body body to encrypt
 * @returns {Object} Encrypted body
 */
function encryptWithHeader(encParams, path, body) {
  const elem = utils.elemFromPath(path.element, body).node;
  const encrypted = this.crypto.encryptData({ data: elem }, encParams);
  const data = {
    [this.config.encryptedValueFieldName]:
      encrypted[this.config.encryptedValueFieldName],
  };
  return utils.isJsonRoot(path.obj) ? data : { [path.obj]: data };
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
    const decryptedObj = this.crypto.decryptData(
      elem.node[this.config.encryptedValueFieldName], // encrypted data
      elem.node[this.config.ivFieldName], // iv field
      elem.node[this.config.oaepHashingAlgorithmFieldName], // oaepHashingAlgorithm
      elem.node[this.config.encryptedKeyFieldName] // encryptedKey
    );
    return utils.mutateObjectProperty(
      path.obj,
      decryptedObj,
      body,
      path.element,
      this.encryptionResponseProperties
    );
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
  const elemEncryptedNode = utils.elemFromPath(path.obj, body);
  const node = utils.isJsonRoot(path.element)
    ? elemEncryptedNode.node
    : elemEncryptedNode.node[path.element];
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
    return utils.isJsonRoot(path.obj) ? decrypted : Object.assign(body, decrypted);
  }
}

module.exports = FieldLevelEncryption;
