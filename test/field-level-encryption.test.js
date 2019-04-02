const assert = require('assert');
const rewire = require("rewire");
const FieldLevelEncryption = rewire("../lib/mcapi/fle/field-level-encryption");

const testConfig = require("./mock/config");

describe("Field Level Encryption", () => {


  describe("#new FieldLevelEncryption", () => {

    it("when valid config", () => {
      let fle = new FieldLevelEncryption(testConfig);
      assert.ok(fle.crypto);
    });

    it("isWithHeader", () => {
      let config = JSON.parse(JSON.stringify(testConfig));
      config["ivHeaderName"] = "ivHeaderName";
      config["encryptedKeyHeaderName"] = "encryptedKeyHeaderName";
      let fle = new FieldLevelEncryption(config);
      assert.ok(fle.isWithHeader);
    });

  });


  describe("#hasConfig", () => {
    let hasConfig = FieldLevelEncryption.__get__("hasConfig");

    it("when valid config, not found endpoint", () => {
      let ret = hasConfig(testConfig, "/endpoint");
      assert.ok(ret === null);
    });

    it("when valid config, found endpoint", () => {
      let ret = hasConfig(testConfig, "/resource");
      assert.ok(ret);
    });

    it("when config is null", () => {
      let ret = hasConfig(null, "/resource");
      assert.ok(ret == null);
    });

    it("when path has wildcard", () => {
      let ret = hasConfig(testConfig, "https://api.example.com/mappings/0123456");
      assert.ok(ret.toEncrypt[0].element === "elem2.encryptedData");
      assert.ok(ret);
    });

  });

  describe("#elemFromPath", () => {
    let elemFromPath = FieldLevelEncryption.__get__("elemFromPath");

    it("valid path", () => {
      let res = elemFromPath("elem1.elem2", {elem1: {elem2: "test"}});
      assert.ok(res.node === 'test');
      assert.ok(JSON.stringify(res.parent) === JSON.stringify({elem2: "test"}));
    });

  });

  describe("#encrypt", () => {
    let fle = new FieldLevelEncryption(testConfig);
    let encrypt = FieldLevelEncryption.__get__("encrypt");

    it("encrypt body payload", () => {
      let res = encrypt.call(fle, "/resource", null,
        {
          elem1: {
            encryptedData: {
              accountNumber: "5123456789012345"
            }
          }
        }
      );
      assert.ok(res.header === null);
      assert.ok(res.body.elem1.encryptedData);
      assert.ok(res.body.elem1.encryptedKey);
      assert.ok(res.body.elem1.iv);
      assert.ok(res.body.elem1.oaepHashingAlgorithm);
      assert.ok(res.body.elem1.publicKeyFingerprint);
    });

    it("encrypt with header", () => {
      let header = {};
      let headerConfig = require("./mock/config-header");
      let fle = new FieldLevelEncryption(headerConfig);
      let encrypt = FieldLevelEncryption.__get__("encrypt");
      let res = encrypt.call(fle, "/resource", header,
        {
          encrypted_payload: {
            data: {
              accountNumber: "5123456789012345"
            }
          }
        }
      );
      assert.ok(res.header[headerConfig.encryptedKeyHeaderName]);
      assert.ok(res.header[headerConfig.ivHeaderName]);
      assert.ok(res.header[headerConfig.oaepHashingAlgorithmHeaderName]);
      assert.ok(res.header[headerConfig.publicKeyFingerprintHeaderName]);
      assert.ok(res.body.encrypted_payload.data.length > "5123456789012345".length);
    });

  });

  describe("#decrypt", () => {
    let fle = new FieldLevelEncryption(testConfig);
    let decrypt = FieldLevelEncryption.__get__("decrypt");

    it("decrypt response", () => {
      let response = require("./mock/response");
      let res = decrypt.call(fle, response);
      assert.ok(res.elem1.encryptedData.accountNumber === "5123456789012345");
    });

    it("decrypt with header", () => {
      let response = require("./mock/response-header");
      let headerConfig = require("./mock/config-header");
      let fle = new FieldLevelEncryption(headerConfig);
      let decrypt = FieldLevelEncryption.__get__("decrypt");
      let res = decrypt.call(fle, response);
      assert.ok(res.accountNumber === "5123456789012345");
    });

    it("decrypt without config", () => {
      let fle = new FieldLevelEncryption(testConfig);
      let response = {request: {url: "/foobar"}, body: "body"};
      let res = decrypt.call(fle, response);
      assert.ok(res === "body");
    });

  });

  describe("#setHeader", () => {
    let headerConfig = require("./mock/config-header");
    let fle = new FieldLevelEncryption(headerConfig);
    let setHeader = FieldLevelEncryption.__get__("setHeader");

    it("set http header from config", () => {
      let header = {};
      let params = {
        encoded: {encryptedKey: "encryptedKey", iv: "iv"},
        oaepHashingAlgorithm: "oaepHashingAlgorithm",
        publicKeyFingerprint: "publicKeyFingerprint"
      };
      setHeader.call(fle, header, params);
      assert.ok(header[headerConfig.encryptedKeyHeaderName] === "encryptedKey");
      assert.ok(header[headerConfig.ivHeaderName] === "iv");
      assert.ok(header[headerConfig.oaepHashingAlgorithmHeaderName] === "oaepHashingAlgorithm");
      assert.ok(header[headerConfig.publicKeyFingerprintHeaderName] === "publicKeyFingerprint");
    });

  });

  describe("#import FieldLevelEncryption", () => {
    it("from mcapi-service", () => {
      let FieldLevelEncryption = require("..").FieldLevelEncryption;
      assert.ok(FieldLevelEncryption);
      let fle = new FieldLevelEncryption(testConfig);
      assert.ok(fle.crypto);
    });
  });

});
