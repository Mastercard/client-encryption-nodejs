# client-encryption-nodejs

[![](https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg)](https://developer.mastercard.com/)

[![](https://github.com/Mastercard/client-encryption-nodejs/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/client-encryption-nodejs/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-nodejs&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-nodejs)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-nodejs&metric=coverage)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-nodejs)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-nodejs&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-nodejs)
[![](https://github.com/Mastercard/client-encryption-nodejs/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/client-encryption-nodejs/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/npm/v/mastercard-client-encryption.svg)](https://www.npmjs.com/package/mastercard-client-encryption)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-nodejs/blob/master/LICENSE)

## Table of Contents

- [Overview](#overview)
  - [Compatibility](#compatibility)
  - [References](#references)
  - [Versioning and Deprecation Policy](#versioning)
- [Usage](#usage)
  - [Prerequisites](#prerequisites)
  - [Adding the Library to Your Project](#adding-the-libraries-to-your-project)
  - [Performing Field Level Encryption and Decryption](#performing-field-level-encryption-and-decryption)
  - [Performing JWE Encryption and Decryption](#performing-jwe-encryption-and-decryption)
  - [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>

NodeJS library for Mastercard API compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>
- NodeJS 16+

There shouldn't be any Node compatibility issues with this package, but it's a good idea to keep your Node versions up-to-date. It is recommended that you use one of the LTS Node.js releases, or one of the more general recent releases. A Node version manager such as `nvm` (_Mac_ and _Linux_) or `nvm-windows` is a good way to stay on top of this.

### References <a name="references"></a>

<img src="https://user-images.githubusercontent.com/3964455/55345820-c520a280-54a8-11e9-8235-407199fa1d97.png" alt="Encryption of sensitive data" width="75%" height="75%"/>

### Versioning and Deprecation Policy <a name="versioning"></a>
* [Mastercard Versioning and Deprecation Policy](https://github.com/Mastercard/.github/blob/main/CLIENT_LIBRARY_DEPRECATION_POLICY.md)

## Usage <a name="usage"></a>

### Prerequisites <a name="prerequisites"></a>

Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com).

As part of this set up, you'll receive:

- A public request encryption certificate (aka _Client Encryption Keys_)
- A private response decryption key (aka _Mastercard Encryption Keys_)

### Installation <a name="adding-the-libraries-to-your-project"></a>

If you want to use **mastercard-client-encryption** with [Node.js](https://nodejs.org/), it is available through `npm`:

- [https://npmjs.org/package/mastercard-client-encryption](https://npmjs.org/package/mastercard-client-encryption)

Adding the library to your project:

```shell
npm install mastercard-client-encryption
```

You can then use it as a regular module:

```js
const clientEncryption = require("mastercard-client-encryption");
```

### Performing Field Level Encryption and Decryption <a name="performing-field-level-encryption-and-decryption"></a>

- [Introduction](#introduction)
- [Configuring the Field Level Encryption](#configuring-the-field-level-encryption)
- [Performing Encryption](#performing-encryption)
- [Performing Decryption](#performing-decryption)

#### Introduction <a name="introduction"></a>

The core methods responsible for payload encryption and decryption are `encryptData` and `decryptData` in the `FieldLevelEncryption` class.

- `encrypt()` usage:

```js
const fle = new clientEncryption.FieldLevelEncryption(config);
// …
let encryptedRequestPayload = fle.encrypt(endpoint, header, body);
```

- `decrypt()` usage:

```js
const fle = new clientEncryption.FieldLevelEncryption(config);
// …
let responsePayload = fle.decrypt(encryptedResponsePayload);
```

#### Configuring the Field Level Encryption <a name="configuring-the-field-level-encryption"></a>

`FieldLevelEncryption` needs a config object to instruct how to decrypt/decrypt the payloads. Example:

```js
const config = {
  paths: [
    {
      path: "/resource",
      toEncrypt: [
        {
          /* path to element to be encrypted in request json body */
          element: "path.to.foo",
          /* path to object where to store encryption fields in request json body */
          obj: "path.to.encryptedFoo",
        },
      ],
      toDecrypt: [
        {
          /* path to element where to store decrypted fields in response object */
          element: "path.to.encryptedFoo",
          /* path to object with encryption fields */
          obj: "path.to.foo",
        },
      ],
    },
  ],
  ivFieldName: "iv",
  encryptedKeyFieldName: "encryptedKey",
  encryptedValueFieldName: "encryptedData",
  dataEncoding: "hex",
  encryptionCertificate: "./path/to/public.cert",
  privateKey: "./path/to/your/private.key",
  oaepPaddingDigestAlgorithm: "SHA-256",
};
```

#### Performing Encryption <a name="performing-encryption"></a>

Call `FieldLevelEncryption.encrypt()` with a JSON request payload, and optional `header` object.

Example using the configuration [above](#configuring-the-field-level-encryption):

```js
const payload = {
  path: {
    to: {
      foo: {
        sensitive: "this is a secret!",
        sensitive2: "this is a super-secret!",
      },
    },
  },
};
const fle = new (require("mastercard-client-encryption").FieldLevelEncryption)(
  config
);
// …
let responsePayload = fle.encrypt("/resource1", header, payload);
```

Output:

```json
{
  "path": {
    "to": {
      "encryptedFoo": {
        "iv": "7f1105fb0c684864a189fb3709ce3d28",
        "encryptedKey": "67f467d1b653d98411a0c6d3c…ffd4c09dd42f713a51bff2b48f937c8",
        "encryptedData": "b73aabd267517fc09ed72455c2…dffb5fa04bf6e6ce9ade1ff514ed6141",
        "publicKeyFingerprint": "80810fc13a8319fcf0e2e…82cc3ce671176343cfe8160c2279",
        "oaepHashingAlgorithm": "SHA256"
      }
    }
  }
}
```

#### Performing Decryption <a name="performing-decryption"></a>

Call `FieldLevelEncryption.decrypt()` with an (encrypted) `response` object with the following fields:

- `body`: json payload
- `request.url`: requesting url
- `header`: _optional_, header object

Example using the configuration [above](#configuring-the-field-level-encryption):

```js
const response = {};
response.request = { url: "/resource1" };
response.body = {
  path: {
    to: {
      encryptedFoo: {
        iv: "e5d313c056c411170bf07ac82ede78c9",
        encryptedKey:
          "e3a56746c0f9109d18b3a2652b76…f16d8afeff36b2479652f5c24ae7bd",
        encryptedData:
          "809a09d78257af5379df0c454dcdf…353ed59fe72fd4a7735c69da4080e74f",
        oaepHashingAlgorithm: "SHA256",
        publicKeyFingerprint: "80810fc13a8319fcf0e2e…3ce671176343cfe8160c2279",
      },
    },
  },
};
const fle = new (require("mastercard-client-encryption").FieldLevelEncryption)(
  config
);
let responsePayload = fle.decrypt(response);
```

Output:

```json
{
  "path": {
    "to": {
      "foo": {
        "sensitive": "this is a secret",
        "sensitive2": "this is a super secret!"
      }
    }
  }
}
```

### Performing JWE Encryption and Decryption <a name="performing-jwe-encryption-and-decryption"></a>

#### JWE Encryption and Decryption <a name="jwe-encryption-and-decryption"></a>

- [Introduction](#jwe-introduction)
- [Configuring the JWE Encryption](#configuring-the-jwe-encryption)
- [Performing JWE Encryption](#performing-jwe-encryption)
- [Performing JWE Decryption](#performing-jwe-decryption)
- [Encrypting Entire Payloads](#encrypting-entire-payloads-jwe)
- [Decrypting Entire Payloads](#decrypting-entire-payloads-jwe)
- [First Level Field Encryption and Decryption](#encrypting-decrypting-first-level-field-jwe)

##### • Introduction <a name="jwe-introduction"></a>

This library uses [JWE compact serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.1) for the encryption of sensitive data.
The core methods responsible for payload encryption and decryption are `encryptData` and `decryptData` in the `JweEncryption` class.

- `encryptPayload` usage:

```js
const jwe = new clientEncryption.JweEncryption(config);
// …
let encryptedRequestPayload = jwe.encrypt(endpoint, header, body);
```

- `decryptPayload` usage:

```js
const jwe = new clientEncryption.JweEncryption(config);
// …
let responsePayload = jwe.decrypt(encryptedResponsePayload);
```

##### • Configuring the JWE Encryption <a name="configuring-the-jwe-encryption"></a>

`JweEncryption` needs a config object to instruct how to decrypt/decrypt the payloads. Example:

```js
const config = {
  paths: [
    {
      path: "/resource1",
      toEncrypt: [
        {
          /* path to element to be encrypted in request json body */
          element: "path.to.foo",
          /* path to object where to store encryption fields in request json body */
          obj: "path.to.encryptedFoo",
        },
      ],
      toDecrypt: [
        {
          /* path to element where to store decrypted fields in response object */
          element: "path.to.encryptedFoo",
          /* path to object with encryption fields */
          obj: "path.to.foo",
        },
      ],
    },
  ],
  mode: "JWE",
  encryptedValueFieldName: "encryptedData",
  encryptionCertificate: "./path/to/public.cert",
  privateKey: "./path/to/your/private.key",
};
```

Mode must be set to JWE to use JWE encryption

##### • Performing JWE Encryption <a name="performing-jwe-encryption"></a>

Call `JweEncryption.encrypt()` with a JSON request payload, and optional `header` object.

Example using the configuration [above](#configuring-the-field-level-encryption):

```js
const payload = {
  path: {
    to: {
      foo: {
        sensitive: "this is a secret!",
        sensitive2: "this is a super-secret!",
      },
    },
  },
};
const jwe = new (require("mastercard-client-encryption").JweEncryption)(config);
// …
let responsePayload = jwe.encrypt("/resource1", header, payload);
```

Output:

```json
{
  "path": {
    "to": {
      "encryptedFoo": {
        "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
      }
    }
  }
}
```

##### • Performing JWE Decryption <a name="performing-jwe-decryption"></a>

Call `JweEncryption.decrypt()` with an (encrypted) `response` object with the following fields:

Example using the configuration [above](#configuring-the-jwe-encryption):

```js
const response = {};
response.request = { url: "/resource1" };
response.body = JSON.parse(
  "{" +
  '    "path": {' +
  '        "to": {' +
  '            "encryptedFoo": {' +
  '                "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"' +
  "            }" +
  "        }" +
  "    }" +
  "}");
const jwe = new (require("mastercard-client-encryption").JweEncryption)(config);
let responsePayload = jwe.decrypt(response);
```

Output:

```json
{
  "path": {
    "to": {
      "foo": {
        "sensitive": "this is a secret",
        "sensitive2": "this is a super secret!"
      }
    }
  }
}
```

##### • Encrypting Entire Payloads <a name="encrypting-entire-payloads-jwe"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

```js
const config = {
  paths: [
    {
      path: "/resource1",
      toEncrypt: [
        {
          /* path to element to be encrypted in request json body */
          element: "$",
          /* path to object where to store encryption fields in request json body */
          obj: "$",
        },
      ],
      toDecrypt: [],
    },
  ],
  mode: "JWE",
  encryptedValueFieldName: "encryptedData",
  encryptionCertificate: "./path/to/public.cert",
  privateKey: "./path/to/your/private.key",
};
```

Example:

```js
const payload = JSON.parse(
  "{" +
  '    "sensitive": "this is a secret",' +
  '    "sensitive2": "this is a super secret!"' +
  "}");
const jwe = new (require("mastercard-client-encryption").JweEncryption)(config);
// …
let responsePayload = jwe.encrypt("/resource1", header, payload);
```

Output:

```json
{
  "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
}
```

##### • Decrypting Entire Payloads <a name="decrypting-entire-payloads-jwe"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

```js
const config = {
  paths: [
    {
      path: "/resource1",
      toEncrypt: [],
      toDecrypt: [
        {
          /* path to element where to store decrypted fields in response object */
          element: "$",
          /* path to object with encryption fields */
          obj: "$",
        },
      ],
    },
  ],
  mode: "JWE",
  encryptedValueFieldName: "encryptedData",
  encryptionCertificate: "./path/to/public.cert",
  privateKey: "./path/to/your/private.key",
};
```

Example:

```js
const encryptedPayload = JSON.parse(
  "{" +
  '  "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"' +
  "}");
const jwe = new (require("mastercard-client-encryption").JweEncryption)(config);
let responsePayload = jwe.decrypt(encryptedPayload);
```

Output:

```json
{
  "sensitive": "this is a secret",
  "sensitive2": "this is a super secret!"
}
```

##### • First Level Field Encryption and Decryption <a name="encrypting-decrypting-first-level-field-jwe"></a>

To have encrypted results in the first level field or to decrypt the first level field, specify `encryptedValueFieldName` to be the same as `obj` (for encryption) or `element` (for decryption):

Example of configuration:

```js
const config = {
  paths: [
    {
      path: "/resource1",
      toEncrypt: [
        {
          /* path to element to be encrypted in request json body */
          element: "sensitive",
          /* path to object where to store encryption fields in request json body */
          obj: "encryptedData",
        },
      ],
      toDecrypt: [
        {
          /* path to element where to store decrypted fields in response object */
          element: "encryptedData",
          /* path to object with encryption fields */
          obj: "sensitive",
        },
      ],
    },
  ],
  mode: "JWE",
  encryptedValueFieldName: "encryptedData",
  encryptionCertificate: "./path/to/public.cert",
  privateKey: "./path/to/your/private.key",
};
```

Example of encryption:

```js
const payload = {
  sensitive: "this is a secret!",
  notSensitive: "not a secret",
};
const jwe = new (require("mastercard-client-encryption").JweEncryption)(config);
// …
let responsePayload = jwe.encrypt("/resource1", header, payload);
```

Output:

```json
{
  "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw",
  "notSensitive": "not a secret"
}
```

Example of decryption:

```js
const response = {};
response.request = { url: "/resource1" };
response.body = JSON.parse(
  "{" +
  '    "encryptedData": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw",' +
  '    "notSensitive": "not a secret"' +
  "}");
const jwe = new (require("mastercard-client-encryption").JweEncryption)(config);
let responsePayload = jwe.decrypt(response);
```

Output:

```json
{
  "sensitive": "this is a secret",
  "notSensitive": "not a secret"
}
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification).
It provides generators and library templates for supporting multiple languages and frameworks.

The **client-encryption-nodejs** library provides the `Service` decorator object you can use with the OpenAPI generated client. This class will take care of encrypting request and decrypting response payloads, but also of updating HTTP headers when needed, automatically, without manually calling `encrypt()`/`decrypt()` functions for each API request or response.

##### OpenAPI Generator <a name="openapi-generator"></a>

OpenAPI client can be generated, starting from your OpenAPI Spec / Swagger using the following command:

```shell
openapi-generator-cli generate -i openapi-spec.yaml -l javascript -o out
```

Client library will be generated in the `out` folder.

See also:

- [OpenAPI Generator CLI Installation](https://openapi-generator.tech/docs/installation/)

##### Usage of the `mcapi-service`:

To use it:

1. Generate the OpenAPI client, as [above](#openapi-generator)

2. Import the **mastercard-client-encryption** library

   ```js
   const mcapi = require("mastercard-client-encryption");
   ```

3. Import the OpenAPI Client using the `Service` decorator object:

   ```js
   const openAPIClient = require("./path/to/generated/openapi/client");
   const config = {
     /* service configuration object */
   };

   const service = new mcapi.Service(openAPIClient, config);
   ```

4. Use the `service` object as you are using the `openAPIClient` to make API requests.

   Example:

   ```js
   let api = service.ServiceApi();
   let merchant =
     /* … */
     api.createMerchants(merchant, (error, data, response) => {
       // requests and responses will be automatically encrypted and decrypted
       // accordingly with the configuration used to instantiate the mcapi.Service.
       /* use response/data object here */
     });
   ```
