const assert = require('assert');
const rewire = require("rewire");
const FieldLevelEncryption = rewire("../lib/mcapi/fle/field-level-encryption");

const testConfig = require("./mock/config");

describe("Payload encryption", () => {

  let config = JSON.parse(JSON.stringify(testConfig));
  config['encryptedValueFieldName'] = "encryptedValue";
  let fle = new FieldLevelEncryption(config);
  let encryptBody = FieldLevelEncryption.__get__("encryptBody");
  let decryptBody = FieldLevelEncryption.__get__("decryptBody");

  describe("#encryptBody", () => {

    it("with sibling", () => {
      let body = {
        data: {
          field1: "value1",
          field2: "value2"
        },
        encryptedData: {}
      };
      encryptBody.call(fle, {
        element: "data",
        obj: "encryptedData"
      }, body);
      assert.ok(!body.data);
      assert.ok(body.encryptedData.encryptedValue);
      assert.ok(body.encryptedData.iv);
      assert.ok(body.encryptedData.encryptedKey);
      assert.ok(body.encryptedData.publicKeyFingerprint);
      assert.ok(body.encryptedData.oaepHashingAlgorithm);
    });

    it("destination obj not exists", () => {
      let body = {
        itemsToEncrypt: {
          first: "first",
          second: "second"
        },
        dontEncrypt: {
          text: "just text..."
        }
      };
      encryptBody.call(fle, {
        element: "itemsToEncrypt",
        obj: "encryptedItems"
      }, body);
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
      let body = {
        itemsToEncrypt: {
          first: "first",
          second: "second"
        },
        dontEncrypt: {
          text: "just text..."
        }
      };
      encryptBody.call(fle, {
        element: "not.found",
        obj: "encryptedItems"
      }, body);
      assert.ok(body.dontEncrypt);
      assert.ok(body.itemsToEncrypt);
      assert.ok(!body.encryptedItems);
    });

    it("nested object to encrypt", () => {
      let body = {
        path: {
          to: {
            encryptedData: {
              sensitive: "secret",
              sensitive2: "secret 2"
            }
          }
        }
      };
      encryptBody.call(fle, {
        element: "path.to.encryptedData",
        obj: "path.to"
      }, body);
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
      let body = {
        path: {
          to: {
            foo: {
              sensitive: "secret",
              sensitive2: "secret 2"
            }
          }
        }
      };
      encryptBody.call(fle, {
        element: "path.to.foo",
        obj: "path.to.encryptedFoo"
      }, body);
      assert.ok(!body.path.to.foo);
      assert.ok(body);
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.encryptedFoo);
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
      let body = {
        path: {
          to: {
            encryptedFoo: {
              encryptedValue:
                '3097e36bf8b71637a0273abe69c23752d6157464ce49f6f35120d28bedfb63a1f2c8087be3a3bc9775592db41db87a8c',
              iv: '22507f596fffb45b15244356981d7ea1',
              encryptedKey:
                'd4714161898b8bc5c54a63f71ae7c7a40734e4f7c7e27d121ac5e85a3fa47946aa3546027abe0874d751d5ae701491a7f572fc30fa08dd671d358746ffe8709cba36010f97864105b175c51b6f32d36d981287698a3f6f8707aedf980cce19bfe7c5286ddba87b7f3e5abbfa88a980779037c0b7902d340d73201cf3f0b546c2ad9f54e4b71a43504da947a3cb7af54d61717624e636a90069be3c46c19b9ae8b76794321b877544dd03f0ca816288672ef361c3e8f14d4a1ee96ba72d21e3a36c020aa174635a8579b0e9af761d96437e1fa167f00888ff2532292e7a220f5bc948f8159dea2541b8c6df6463213de292b4485076241c90706efad93f9b98ea',
              publicKeyFingerprint:
                '80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279',
              oaepHashingAlgorithm: 'SHA512'
            }
          }
        }
      };
      decryptBody.call(fle, {
        element: "path.to.encryptedFoo",
        obj: "path.to.foo"
      }, body);
      assert.ok(!body.path.to.encryptedFoo);
      assert.ok(body);
      assert.ok(body.path);
      assert.ok(body.path.to);
      assert.ok(body.path.to.foo);
      assert.ok(body.path.to.foo.accountNumber === "5123456789012345");
    });
  });

});
