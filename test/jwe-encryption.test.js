const assert = require("assert");
const rewire = require("rewire");
const JweEncryption = rewire("../lib/mcapi/encryption/jwe-encryption");
const utils = require("../lib/mcapi/utils/utils");

const testConfig = require("./mock/jwe-config");

describe("JWE Encryption", () => {
  before(function () {
    if (!utils.nodeVersionSupportsJWE()) {
      this.skip();
    }
  });

  describe("#new JWEEncryption", () => {
    it("when valid config", () => {
      const encryption = new JweEncryption(testConfig);
      assert.ok(encryption.crypto);
    });
  });

  describe("#encrypt", () => {
    it("encrypt body payload", () => {
      const encryption = new JweEncryption(testConfig);
      const encrypt = JweEncryption.__get__("encrypt");
      const res = encrypt.call(encryption, "/resource", null, {
        elem1: {
          encryptedData: {
            accountNumber: "5123456789012345",
          },
          shouldBeThere: "shouldBeThere",
        },
      });
      assert.ok(res.header === null);
      assert.ok(res.body.elem1.shouldBeThere);
      assert.ok(res.body.elem1.encryptedData);
      assert.ok(!res.body.elem1.encryptedData.accountNumber);
    });
  });

  describe("#encrypt without toEncrypt", () => {
    it("returns body untouched", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.paths[0].toEncrypt;
      const encryption = new JweEncryption(config);
      const encrypt = JweEncryption.__get__("encrypt");
      const body = { elem1: { encryptedData: { accountNumber: "5123456789012345" } } };
      const res = encrypt.call(encryption, "/resource", null, body);
      assert.ok(res.header === null);
      assert.ok(res.body === body);
    });
  });

  describe("#decrypt", () => {
    it("decrypt response", () => {
      const encryption = new JweEncryption(testConfig);
      const decrypt = JweEncryption.__get__("decrypt");
      const response = require("./mock/jwe-response");
      const res = decrypt.call(encryption, response);
      assert.ok(res.foo.accountNumber === "5123456789012345");
      assert.ok(!res.foo.elem1);
      assert.ok(
        !Object.prototype.hasOwnProperty.call(res.foo, "encryptedData")
      );
    });

    it("returns body untouched when toDecrypt is not defined", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.paths[0].toDecrypt;
      const encryption = new JweEncryption(config);
      const decrypt = JweEncryption.__get__("decrypt");
      const response = JSON.parse(JSON.stringify(require("./mock/jwe-response")));
      const res = decrypt.call(encryption, response);
      assert.ok(res === response.body);
    });

    it("decrypt first level element in response", () => {
      const encryption = new JweEncryption(testConfig);
      const decrypt = JweEncryption.__get__("decrypt");
      const response = require("./mock/jwe-response");
      const res = decrypt.call(encryption, response);
      assert.ok(res.decryptedData.accountNumber === "5123456789012345");
      assert.ok(!res.encryptedData);
    });
  });

  describe("#import JweEncryption", () => {
    it("from mcapi-service", () => {
      const JweEncryption = require("..").JweEncryption;
      assert.ok(JweEncryption);
      const jwe = new JweEncryption(testConfig);
      assert.ok(jwe.crypto);
    });
  });
});
