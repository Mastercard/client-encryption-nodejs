const assert = require('assert');
const rewire = require("rewire");
const FieldLevelEncryption = rewire("../lib/mcapi/fle/field-level-encryption");

const testConfig = require("./mock/config");

describe("Payload encryption", () => {

  let config = JSON.parse(JSON.stringify(testConfig));
  config['encryptedValueFieldName'] = "encryptedValue";
  let fle = new FieldLevelEncryption(config);
  let encryptBody = FieldLevelEncryption.__get__("encryptBody");

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

  });

});
