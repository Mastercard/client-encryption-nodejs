const assert = require("assert");
const rewire = require("rewire");
const JweEncryption = rewire("../lib/mcapi/encryption/jwe-encryption");
const utils = require("../lib/mcapi/utils/utils");

const testConfig = require("./mock/jwe-config");
const encryptedData = "eyJraWQiOiJnSUVQd1RxREdmenc0dXd5TElLa3d3UzNnc3c4NW5FWFkwUFA2QllNSW5rPSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24iLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.bg6UTkMY9omV6CpXZnTsLNDQgKHVSOf7pO4KxhjkQfYSM6I2WBLNL8TMVFuVnOwGnq7jXwBBtszIj0Enk7nmwme2VNKnBEyoe-1t99j1VPX7CVQIdezNnJbwFl746Vi-izt6fatRPHUbp47pvZ7qL8u_xS9Ucv8-1HxuykoVbiHcY1lb-Mm_dzEJf-2eG0fkJxuVJBtUktrO0nu6BC_D53UULTxju6goGcjmgOqrAzf4Yg0NRrzObLchWisbzVcbzO0Lnv0rxDYYIeN54BSKpKowglQ8EElKqLx3rCZ8is6Un2nKqhzsY52-DAZ5-HLSCDCyjEO6CB1w8Y2CXvANZg.B5pVI2hqtwLFuiCNnzonAw.ZDnLiPNy63ocuwhYQFfSneS13Ff5GlFc87kegf8mnAJxGsYS.YFistvxKLMfLGVY5vWV_Dw";

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

    it("encrypt request body with arrays", () => {
      // arrange
      const pathUrl = "encrypt/array/one";
      testConfig.paths.push(
        {
          path: pathUrl,
          toEncrypt: [
            {
              element: "*.elem1",
              obj: "*",
            }
          ],
          toDecrypt: [],
        });
      const request = [
        { elem1: { accountNumber: "5123456789012345"}, elem2: "value" },
        { elem1: { accountNumber: "5123456789012345"}, elem2: "value" }
      ];

      const encryption = new JweEncryption(testConfig);
      const encrypt = JweEncryption.__get__("encrypt");

      // act
      const res = encrypt.call(encryption, pathUrl, null, request);

      // assert
      assert.ok(res.body[0].encryptedData);
      assert.ok(res.body[1].encryptedData);
      assert.ok(res.body[0].elem2);
      assert.ok(res.body[1].elem2);
      assert.ok(!res.body[0].elem1);
      assert.ok(!res.body[1].elem1);
      assert.ok(
        !Object.prototype.hasOwnProperty.call(res.body[0], "elem1")
      );
    });

    it("encrypt request body with multiple arrays", () => {
      // arrange
      const pathUrl = "encrypt/array/two";
      testConfig.paths.push(
        {
          path: pathUrl,
          toEncrypt: [
            {
              element: "*.elem1.*",
              obj: "*.elem1.*",
            }
          ],
          toDecrypt: [],
        });
      const request = [
        { elem1: [{ accountNumber: "5123456789012345"}, { accountNumber: "5123456789012345"}], elem2: "value" },
        { elem1: [{ accountNumber: "5123456789012345"}, { accountNumber: "5123456789012345"}], elem2: "value" }
      ];

      const encryption = new JweEncryption(testConfig);
      const encrypt = JweEncryption.__get__("encrypt");

      // act
      const res = encrypt.call(encryption, pathUrl, null, request);

      // assert
      assert.ok(res.body[0].elem1[0].encryptedData);
      assert.ok(res.body[0].elem1[1].encryptedData);
      assert.ok(res.body[1].elem1[0].encryptedData);
      assert.ok(res.body[1].elem1[1].encryptedData);
      assert.ok(res.body[0].elem2);
      assert.ok(res.body[1].elem2);
      assert.ok(!res.body[0].elem1[0].accountNumber);
      assert.ok(!res.body[1].elem1[1].accountNumber);
      assert.ok(
        !Object.prototype.hasOwnProperty.call(res.body[0].elem1[0], "accountNumber")
      );
    });

    it("encrypt request body with arrays to new field", () => {
      // arrange
      const pathUrl = "encrypt/array/three";
      testConfig.paths.push(
        {
          path: pathUrl,
          toEncrypt: [
            {
              element: "*.elem1",
              obj: "*.newElem",
            }
          ],
          toDecrypt: [],
        });
      const request = [
        { elem1: { accountNumber: "5123456789012345"}, elem2: "value" },
        { elem1: { accountNumber: "5123456789012345"}, elem2: "value" }
      ];

      const encryption = new JweEncryption(testConfig);
      const encrypt = JweEncryption.__get__("encrypt");

      // act
      const res = encrypt.call(encryption, pathUrl, null, request);

      // assert
      assert.ok(res.body[0].newElem.encryptedData);
      assert.ok(res.body[1].newElem.encryptedData);
      assert.ok(res.body[0].elem2);
      assert.ok(res.body[1].elem2);
      assert.ok(!res.body[0].elem1);
      assert.ok(!res.body[1].elem1);
      assert.ok(
        !Object.prototype.hasOwnProperty.call(res.body[0], "elem1")
      );
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

    it("decrypt response body with arrays", () => {
      // arrange
      const pathUrl = "decrypt/array/one";
      testConfig.paths.push(
        {
          path: pathUrl,
          toEncrypt: [],
          toDecrypt: [
            {
              element: "elem2.*.elem3.*",
              obj: "elem2.*.elem3.*",
            }
          ],
        });
      const response = {
        request: { url: pathUrl },
        body: {
          elem1: { elem2: "value"},
          elem2: [{ elem3: [{ encryptedData: encryptedData, elem5: "value" }]}, { elem3: [{ encryptedData : encryptedData, elem5: "value" }]}]
        }
      };

      const encryption = new JweEncryption(testConfig);
      const decrypt = JweEncryption.__get__("decrypt");

      // act
      const res = decrypt.call(encryption, response);

      // assert
      assert.strictEqual(res.elem2[0].elem3[0].accountNumber, "5123456789012345");
      assert.strictEqual(res.elem2[1].elem3[0].accountNumber, "5123456789012345");
      assert.ok(res.elem2[0].elem3[0].elem5);
      assert.ok(!res.elem2[0].elem3[0].encryptedData);
      assert.ok(
        !Object.prototype.hasOwnProperty.call(res.elem2[0].elem3[0], "encryptedData")
      );
    });

    it("decrypt response body with arrays to new element", () => {
      // arrange
      const pathUrl = "decrypt/array/two";
      testConfig.paths.push(
        {
          path: pathUrl,
          toEncrypt: [],
          toDecrypt: [
            {
              element: "*.elem1",
              obj: "*.elem1.newElem",
            }
          ],
        });
      const response = {
        request: { url: pathUrl },
        body: [{ elem1: { encryptedData: encryptedData }, elem2: "value" }, { elem1: { encryptedData : encryptedData }, elem2: "value" }]
      };

      const encryption = new JweEncryption(testConfig);
      const decrypt = JweEncryption.__get__("decrypt");

      // act
      const res = decrypt.call(encryption, response);

      // assert
      assert.strictEqual(res[0].elem1.newElem.accountNumber, "5123456789012345");
      assert.strictEqual(res[1].elem1.newElem.accountNumber, "5123456789012345");
      assert.ok(!res[0].elem1.encryptedData);
      assert.ok(res[0].elem2);
      assert.ok(
        !Object.prototype.hasOwnProperty.call(res[0].elem1, "encryptedData")
      );
    });

    it("decrypt response body with arrays where path is ended with wildcard", () => {
      // arrange
      const pathUrl = "decrypt/array/three";
      testConfig.paths.push(
        {
          path: pathUrl,
          toEncrypt: [],
          toDecrypt: [
            {
              element: "*",
              obj: "*",
            }
          ],
        });
      const response = {
        request: { url: pathUrl },
        body: [{ encryptedData: encryptedData, elem2: "value" }, { encryptedData : encryptedData, elem2: "value" }]
      };

      const encryption = new JweEncryption(testConfig);
      const decrypt = JweEncryption.__get__("decrypt");

      // act
      const res = decrypt.call(encryption, response);

      // assert
      assert.strictEqual(res[0].accountNumber, "5123456789012345");
      assert.strictEqual(res[1].accountNumber, "5123456789012345");
      assert.ok(res[0].elem2);
      assert.ok(!res[0].encryptedData);
      assert.ok(
        !Object.prototype.hasOwnProperty.call(res[0], "encryptedData")
      );
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
