const forge = require('node-forge');

/**
 * Utils module
 * @Module Utils
 * @version 1.0.0
 */

/**
 * Check if a value is set
 * @param value value to check
 * @returns {boolean} True if set, false otherwise
 */
module.exports.isSet = function (value) {
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
  if (typeof bytes === "undefined" || bytes === null) {
    throw new Error("Input not valid");
  }
  switch (dataEncoding.toLowerCase()) {
    case 'hex':
      return forge.util.bytesToHex(bytes);
    case 'base64':
    default:
      return forge.util.encode64(bytes);
  }
};

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
    case 'hex':
      return forge.util.hexToBytes(value);
    case 'base64':
    default:
      return forge.util.decode64(value);
  }
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

module.exports.mutateObjectProperty = function (path, value, obj, toEncrypt) {
  let tmp = obj;
  let prev = null;
  if (path) {
    let paths = path.split(".");
    paths.forEach((e) => {
      if (!tmp.hasOwnProperty(e)) {
        tmp[e] = {};
      }
      prev = tmp;
      tmp = tmp[e];
    });
    if (toEncrypt && prev) {
      delete prev[toEncrypt];
    }
    let elem = path.split(".").pop();
    if (prev && prev.hasOwnProperty(elem)) {
      if (typeof value === 'object') {
        overrideProperties(prev[elem], value);
      } else {
        prev[elem] = value;
      }
    }
  }
};

/**
 * Resolve object property using dynamic path
 * @param path path in dotted format, example: "first.second.third"
 * @param obj Object to query
 * @param create {boolean} create the node if not found
 * @returns the queried property or null if not found
 */
module.exports.resolveNode = function (path, obj, create) {
  if (path && path.length > 0 && obj) {
    return path.split('.').reduce(function (prev, curr) {
      if (create && !prev[curr]) {
        prev[curr] = {};
      }
      return prev[curr] ? prev[curr] : null;
    }, obj);
  } else return null;
};

function overrideProperties(target, obj) {
  for (let k in obj) {
    target[k] = obj[k];
  }
}
