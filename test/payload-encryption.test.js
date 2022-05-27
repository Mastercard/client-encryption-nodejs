const assert = require("assert");
const rewire = require("rewire");
const FieldLevelEncryption = rewire(
  "../lib/mcapi/encryption/field-level-encryption"
);
const JweEncryption = rewire("../lib/mcapi/encryption/jwe-encryption");
const utils = require("../lib/mcapi/utils/utils");

const testConfig = require("./mock/config");
const jweTestConfig = require("./mock/jwe-config");

describe("Payload encryption", () => {
  const config = JSON.parse(JSON.stringify(testConfig));
  config["encryptedValueFieldName"] = "encryptedValue";
  const jweConfig = JSON.parse(JSON.stringify(jweTestConfig));
  jweConfig["encryptedValueFieldName"] = "encryptedValue";
  const fle = new FieldLevelEncryption(config);
  const encryptBody = FieldLevelEncryption.__get__("encryptBody");
  const decryptBody = FieldLevelEncryption.__get__("decryptBody");

  describe("#encryptBody", () => {
    it("with sibling", () => {
      const body = {
        data: {
          field1: "value1",
          field2: "value2",
        },
        encryptedData: {},
      };
      encryptBody.call(
        fle,
        {
          element: "data",
          obj: "encryptedData",
        },
        body
      );
      assert.ok(!body.data);
      assert.ok(body.encryptedData.encryptedValue);
      assert.ok(body.encryptedData.iv);
      assert.ok(body.encryptedData.encryptedKey);
      assert.ok(body.encryptedData.publicKeyFingerprint);
      assert.ok(body.encryptedData.oaepHashingAlgorithm);
    });

    it("destination obj not exists", () => {
      const body = {
        itemsToEncrypt: {
          first: "first",
          second: "second",
        },
        dontEncrypt: {
          text: "just text...",
        },
      };
      encryptBody.call(
        fle,
        {
          element: "itemsToEncrypt",
          obj: "encryptedItems",
        },
        body
      );
      assert.ok(body.dontEncrypt);
      assert.ok(!body.itemsToEncrypt);
      assert.ok(body.encryptedItems);
      assert.ok(body.encryptedItems.iv);
      assert.ok(body.encryptedItems.encryptedValue);
      assert.ok(body.encryptedItems.encryptedKey);
      assert.ok(body.encryptedItems.publicKeyFingerprint);
      assert.ok(body.encryptedItems.oaepHashingAlgorithm);
    });

    it("elem not found", () => {
      const body = {
        itemsToEncrypt: {
          first: "first",
          second: "second",
        },
        dontEncrypt: {
          text: "just text...",
        },
      };
      encryptBody.call(
        fle,
        {
          element: "not.found",
          obj: "encryptedItems",
        },
        body
      );
      assert.ok(body.dontEncrypt);
      assert.ok(body.itemsToEncrypt);
      assert.ok(!body.encryptedItems);
    });

    it("nested object to encrypt", () => {
      const body = {
        path: {
          to: {
            encryptedData: {
              sensitive: "secret",
              sensitive2: "secret 2",
            },
          },
        },
      };
      encryptBody.call(
        fle,
        {
          element: "path.to.encryptedData",
          obj: "path.to",
        },
        body
      );
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.encryptedValue);
      assert.ok(body.path.to.iv);
      assert.ok(body.path.to.encryptedKey);
      assert.ok(body.path.to.publicKeyFingerprint);
      assert.ok(body.path.to.oaepHashingAlgorithm);
      assert.ok(!body.path.to.encryptedData);
    });

    it("nested object, create different nested object and delete it", () => {
      const body = {
        path: {
          to: {
            foo: {
              sensitive: "secret",
              sensitive2: "secret 2",
            },
          },
        },
      };
      encryptBody.call(
        fle,
        {
          element: "path.to.foo",
          obj: "path.to.encryptedFoo",
        },
        body
      );
      assert.ok(!body.path.to.foo);
      assert.ok(body);
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.encryptedFoo);
      assert.ok(body.path.to.encryptedFoo.iv);
      assert.ok(body.path.to.encryptedFoo.encryptedValue);
      assert.ok(body.path.to.encryptedFoo.encryptedKey);
      assert.ok(body.path.to.encryptedFoo.publicKeyFingerprint);
      assert.ok(body.path.to.encryptedFoo.oaepHashingAlgorithm);
    });
  });

  describe("#decryptBody", () => {
    it("nested properties, create new obj", () => {
      const body = {
        path: {
          to: {
            encryptedFoo: {
              encryptedValue:
                "3097e36bf8b71637a0273abe69c23752d6157464ce49f6f35120d28bedfb63a1f2c8087be3a3bc9775592db41db87a8c",
              iv: "22507f596fffb45b15244356981d7ea1",
              encryptedKey:
                "d4714161898b8bc5c54a63f71ae7c7a40734e4f7c7e27d121ac5e85a3fa47946aa3546027abe0874d751d5ae701491a7f572fc30fa08dd671d358746ffe8709cba36010f97864105b175c51b6f32d36d981287698a3f6f8707aedf980cce19bfe7c5286ddba87b7f3e5abbfa88a980779037c0b7902d340d73201cf3f0b546c2ad9f54e4b71a43504da947a3cb7af54d61717624e636a90069be3c46c19b9ae8b76794321b877544dd03f0ca816288672ef361c3e8f14d4a1ee96ba72d21e3a36c020aa174635a8579b0e9af761d96437e1fa167f00888ff2532292e7a220f5bc948f8159dea2541b8c6df6463213de292b4485076241c90706efad93f9b98ea",
              publicKeyFingerprint:
                "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
              oaepHashingAlgorithm: "SHA512",
            },
          },
        },
      };
      decryptBody.call(
        fle,
        {
          element: "path.to.encryptedFoo",
          obj: "path.to.foo",
        },
        body
      );
      assert.ok(!body.path.to.encryptedFoo);
      assert.ok(body);
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.foo);
      assert.ok(body.path.to.foo.accountNumber === "5123456789012345");
    });

    it("primitive type", () => {
      const body = {
        data: {
          encryptedValue: "e2d6a3a76ea6e605e55b400e5a4eba11",
          iv: "3ce861359fa1630c7a794901ee14bf41",
          encryptedKey:
            "02bb8d5c7d113ef271f199c09f0d76db2b6d5d2d209ad1a20dbc4dd0d04576a92ceb917eea5f403ccf64c3c39dda564046909af96c82fad62f89c3cbbec880ea3105a0a171af904cd3b86ea68991202a2795dca07050ca58252701b7ecea06055fd43e96f4beee48b6275e86af93c88c21994ff46f0610171bd388a2c0a1f518ffc8346f7f513f3283feae5b102c8596ddcb2aea5e62ceb17222e646c599f258463405d28ac012bfd4cc431f94111ee07d79e660948485e38c13cdb8bba8e1df3f7dba0f4c77696f71930533c955f3a430658edaa03b0b0c393934d60f5ac3ea5c06ed64bf969fc01942eac432b8e0c56f7538659a72859d445d150c169ae690",
          publicKeyFingerprint:
            "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79",
          oaepHashingAlgorithm: "SHA256",
        },
      };
      decryptBody.call(
        fle,
        {
          element: "data",
          obj: "data",
        },
        body
      );
      assert.ok(body);
      assert.ok(body.data === "string");
    });
  });

  describe("#encryptBodyJwe", () => {
    before(function () {
      if (!utils.nodeVersionSupportsJWE()) {
        this.skip();
      }
    });

    it("jwe with sibling", () => {
      const jweFle = new JweEncryption(jweConfig);
      const body = {
        data: {
          field1: "value1",
          field2: "value2",
        },
        encryptedData: {},
      };
      encryptBody.call(
        jweFle,
        {
          element: "data",
          obj: "encryptedData",
        },
        body
      );
      assert.ok(!body.data);
      assert.ok(body.encryptedData.encryptedValue);
    });

    it("jwe destination obj not exists", () => {
      const jweFle = new JweEncryption(jweConfig);
      const body = {
        itemsToEncrypt: {
          first: "first",
          second: "second",
        },
        dontEncrypt: {
          text: "just text...",
        },
      };
      encryptBody.call(
        jweFle,
        {
          element: "itemsToEncrypt",
          obj: "encryptedItems",
        },
        body
      );
      assert.ok(body.dontEncrypt);
      assert.ok(!body.itemsToEncrypt);
      assert.ok(body.encryptedItems);
      assert.ok(body.encryptedItems.encryptedValue);
    });

    it("jwe elem not found", () => {
      const jweFle = new JweEncryption(jweConfig);
      const body = {
        itemsToEncrypt: {
          first: "first",
          second: "second",
        },
        dontEncrypt: {
          text: "just text...",
        },
      };
      encryptBody.call(
        jweFle,
        {
          element: "not.found",
          obj: "encryptedItems",
        },
        body
      );
      assert.ok(body.dontEncrypt);
      assert.ok(body.itemsToEncrypt);
      assert.ok(!body.encryptedItems);
    });

    it("jwe nested object to encrypt", () => {
      const jweFle = new JweEncryption(jweConfig);
      const body = {
        path: {
          to: {
            encryptedData: {
              sensitive: "secret",
              sensitive2: "secret 2",
            },
          },
        },
      };
      encryptBody.call(
        jweFle,
        {
          element: "path.to.encryptedData",
          obj: "path.to",
        },
        body
      );
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.encryptedValue);
      assert.ok(!body.path.to.encryptedData);
    });

    it("jwe nested object, create different nested object and delete it", () => {
      const jweFle = new JweEncryption(jweConfig);
      const body = {
        path: {
          to: {
            foo: {
              sensitive: "secret",
              sensitive2: "secret 2",
            },
          },
        },
      };
      encryptBody.call(
        jweFle,
        {
          element: "path.to.foo",
          obj: "path.to.encryptedFoo",
        },
        body
      );
      assert.ok(!body.path.to.foo);
      assert.ok(body);
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.encryptedFoo);
      assert.ok(body.path.to.encryptedFoo.encryptedValue);
    });
  });

  describe("#decryptBodyJwe", () => {
    before(function () {
      if (!utils.nodeVersionSupportsJWE()) {
        this.skip();
      }
    });

    it("jwe nested properties, create new obj", () => {
      const jweFle = new JweEncryption(jweConfig);
      const body = {
        path: {
          to: {
            encryptedFoo: {
              encryptedValue:
                "eyJraWQiOiJnSUVQd1RxREdmenc0dXd5TElLa3d3UzNnc3c4NW5FWFkwUFA2QllNSW5rPSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24iLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.6lSH7gbbarhjRh4YJKqhGZM3zpi33nuUOeBJSVfpVc55WzMnR2gHBcsTUIonAQYm2BE-TwCc4StjydjXzxnUFNsnD0Hx-l5_Ge9QGDr5VsQdt86vkzx2QEM6LKONnUmIE9rC8dA3Rh6UhaM5jo1fDq7awdqxttGqG5haXODC2FRwePgm44foSW8P-T378enucPbMbfgl1nGLA2JWBKPlsPYfSYf87s9FLmGZvJ9wTWH74-Bh_Ie7MvLAyqrpRZ0_dyRFpSTA_pjmt3lfpFCMm3Dk65kH0T01o6bSnxZMfWvrqVx7kiXOrRYVldNm4zqu3puU4_e5rqHKYyceF0DWSw.QPZnTMrNsLpLzqKiGSZZRQ.faGFTTOeLnPGJUTRlLpjE_jD9hrTak9s1wMMXQrFiCf0nBZ7.gdYK250VuTutnxz1ej1MUQ",
            },
          },
        },
      };
      decryptBody.call(
        jweFle,
        {
          element: "path.to.encryptedFoo",
          obj: "path.to.foo",
        },
        body
      );
      assert.ok(!body.path.to.encryptedFoo);
      assert.ok(body);
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.foo);
      assert.ok(body.path.to.foo.accountNumber === "5123456789012345");
    });
  });
});
