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

describe("#", () => {
  it("entire payload encryption and decryption where request and response object is different", () => {
    const encryption = new JweEncryption(testConfig);
    const encrypt = JweEncryption.__get__("encrypt");
    const encryptedPayload = encrypt.call(encryption, "/entirepayload", null,
      {
        externalReference: "48956hguyguy23g4234",
        amount: "2",
        payers: [{ accountAlias: "stg_earmark_payer1withcryptoaddr", amount: "2" }],
        recipients: [{ accountAlias: "stg_earmark_recip1WithCryptoAddr", amount: "1" }]
      });
    encryptedPayload.body.encryptedResponse = encryptedPayload.body.encryptedData;
    delete encryptedPayload.body.encryptedData;

    const decrypt = JweEncryption.__get__("decrypt");
    encryptedPayload.request = { url: "/entirepayload" }
    const res = decrypt.call(encryption, encryptedPayload);
    assert.ok(res.externalReference === "48956hguyguy23g4234");
    assert.ok(res.amount === "2");
    assert.ok(res.payers[0].accountAlias === "stg_earmark_payer1withcryptoaddr");
    assert.ok(res.recipients[0].accountAlias === "stg_earmark_recip1WithCryptoAddr");
  });
});