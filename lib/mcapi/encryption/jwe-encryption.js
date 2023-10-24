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
  const pathsToFieldsToBeEncrypted = utils.replaceWildcardsWithIndexes(path.element, body);
  const splitPathsToEncryptedFields = utils.splitPathByLastWildcard(path.obj);
  const pathsToEncryptedFields = utils.replaceWildcardsWithIndexes(splitPathsToEncryptedFields[0], body);

  pathsToFieldsToBeEncrypted.forEach((subPath, index) => {
    const elem = utils.elemFromPath(subPath, body);
    if (elem && elem.node) {
      const pathToEncryptedFields = splitPathsToEncryptedFields.length === 1 ?
        pathsToEncryptedFields[index] : pathsToEncryptedFields[index] + splitPathsToEncryptedFields[1];
      const newPath = {element: subPath, obj: pathToEncryptedFields};
      const encryptedData = this.crypto.encryptData({data: elem.node});
      body = utils.addEncryptedDataToBody(encryptedData, newPath, this.config.encryptedValueFieldName, body);
    }
  });
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
  const pathsToEncryptedFields = utils.replaceWildcardsWithIndexes(path.element, body);
  const splitPathsToDecryptedFields = utils.splitPathByLastWildcard(path.obj);
  const pathsToDecryptedFields = utils.replaceWildcardsWithIndexes(splitPathsToDecryptedFields[0], body);

  pathsToEncryptedFields.forEach((subPath, index) => {
    const elem = utils.elemFromPath(subPath, body);
    if (elem && elem.node) {
      const encryptedValue = (subPath === this.config.encryptedValueFieldName) ?
        elem.node : elem.node[this.config.encryptedValueFieldName];
      // in case we have path to Array index we do not want to delete entire node but just encrypted field
      const pathToDelete = isNaN(subPath.split(".").pop()) ?
        subPath : subPath + "." + this.config.encryptedValueFieldName;
      const decryptedObj = this.crypto.decryptData(encryptedValue);
      const pathToDecryptedFields = splitPathsToDecryptedFields.length === 1 ?
        pathsToDecryptedFields[index] : pathsToDecryptedFields[index] + splitPathsToDecryptedFields[1];
      body = utils.mutateObjectProperty(
        pathToDecryptedFields,
        decryptedObj,
        body,
        pathToDelete,
        []
      );
    }
  });

  return body;
}

module.exports = JweEncryption;
