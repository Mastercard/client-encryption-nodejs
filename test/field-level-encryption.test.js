const assert = require('assert');
const rewire = require("rewire");
const FieldLevelEncryption = rewire("../lib/mcapi/fle/field-level-encryption");

const testConfig = require("./mock/config");

describe("Field Level Encryption", () => {


  describe("#new FieldLevelEncryption", () => {

    it("when valid config", () => {
      const fle = new FieldLevelEncryption(testConfig);
      assert.ok(fle.crypto);
    });

    it("isWithHeader", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config["ivHeaderName"] = "ivHeaderName";
      config["encryptedKeyHeaderName"] = "encryptedKeyHeaderName";
      const fle = new FieldLevelEncryption(config);
      assert.ok(fle.isWithHeader);
    });

  });


  describe("#hasConfig", () => {
    const hasConfig = FieldLevelEncryption.__get__("hasConfig");

    it("when valid config, not found endpoint", () => {
      const ret = hasConfig(testConfig, "/endpoint");
      assert.ok(ret === null);
    });

    it("when valid config, found endpoint", () => {
      const ret = hasConfig(testConfig, "/resource");
      assert.ok(ret);
    });

    it("when config is null", () => {
      const ret = hasConfig(null, "/resource");
      assert.ok(ret == null);
    });

    it("when path has wildcard", () => {
      const ret = hasConfig(testConfig, "https://api.example.com/mappings/0123456");
      assert.ok(ret.toEncrypt[0].element === "elem2.encryptedData");
      assert.ok(ret);
    });

  });

  describe("#elemFromPath", () => {
    const elemFromPath = FieldLevelEncryption.__get__("elemFromPath");

    it("valid path", () => {
      const res = elemFromPath("elem1.elem2", {elem1: {elem2: "test"}});
      assert.ok(res.node === 'test');
      assert.ok(JSON.stringify(res.parent) === JSON.stringify({elem2: "test"}));
    });

    it("not valid path", () => {
      const res = elemFromPath("elem1.elem2", {elem2: "test"});
      assert.ok(!res);
    });

  });

  describe("#encrypt", () => {
    const fle = new FieldLevelEncryption(testConfig);
    const encrypt = FieldLevelEncryption.__get__("encrypt");

    it("encrypt body payload", () => {
      const res = encrypt.call(fle, "/resource", null,
        {
          elem1: {
            encryptedData: {
              accountNumber: "5123456789012345"
            },
            shouldBeThere: "here I'am"
          }
        }
      );
      assert.ok(res.header === null);
      assert.ok(res.body.elem1.shouldBeThere);
      assert.ok(res.body.elem1.encryptedData);
      assert.ok(res.body.elem1.encryptedKey);
      assert.ok(res.body.elem1.iv);
      assert.ok(res.body.elem1.oaepHashingAlgorithm);
      assert.ok(res.body.elem1.publicKeyFingerprint);
      assert.ok(!res.body.elem1.encryptedData.accountNumber);
    });

    it("encrypt body payload with readme config", () => {
      const testConfigReadme = require("./mock/config-readme");
      const fle = new FieldLevelEncryption(testConfigReadme);
      const encrypt = FieldLevelEncryption.__get__("encrypt");
      const res = encrypt.call(fle, "/resource", null,
        {
          path: {
            to: {
              encryptedData: {
                sensitive: "this is a secret",
                sensitive2: "this is a super secret!"
              }
            }
          }
        }
      );
      assert.ok(res.header === null);
      assert.ok(!res.body.path.to.encryptedData.sensitive);
      assert.ok(!res.body.path.to.encryptedData.sensitive2);
      assert.ok(res.body.path);
      assert.ok(res.body.path.to);
      assert.ok(res.body.path.to.encryptedData);
      assert.ok(!res.body.path.to.encryptedData.sensitive);
      assert.ok(res.body.path.to.iv);
      assert.ok(res.body.path.to.encryptedKey);
      assert.ok(res.body.path.to.publicKeyFingerprint);
      assert.ok(res.body.path.to.oaepHashingAlgorithm);
    });

    it("encrypt with header", () => {
      const header = {};
      const headerConfig = require("./mock/config-header");
      const fle = new FieldLevelEncryption(headerConfig);
      const encrypt = FieldLevelEncryption.__get__("encrypt");
      const res = encrypt.call(fle, "/resource", header,
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

    it("encrypt when config not found", () => {

      const body = {
        elem1: {
          encryptedData: {
            accountNumber: "5123456789012345"
          }
        }
      };
      const res = encrypt.call(fle, "/not-exists", null, body);
      assert.ok(res.header === null);
      assert.ok(JSON.stringify(res.body) === JSON.stringify(body));
    });

    it("encrypt root arrays", () => {
      const body = [{}, {}];
      const fle = new FieldLevelEncryption(testConfig);
      const res = encrypt.call(fle, "/array-resp", null, body);

      assert.ok(res.body.iv);
      assert.ok(res.body.encryptedData);
      assert.ok(res.body.encryptedKey);
      assert.ok(res.body.publicKeyFingerprint);
      assert.ok(res.body.oaepHashingAlgorithm);

      const response = {request: {url: "/array-resp"}, body: res.body};
      const decrypted = FieldLevelEncryption.__get__("decrypt").call(fle, response);

      assert.ok(JSON.stringify(body) === JSON.stringify(decrypted));
    });

    it("encrypt root arrays with header config", () => {
      const header = {};
      const body = [{}, {}];
      const fle = new FieldLevelEncryption(require("./mock/config-header"));
      const res = encrypt.call(fle, "/array-resp", header, body);

      const response = {request: {url: "/array-resp"}, body: res.body, header: header};
      const decrypted = FieldLevelEncryption.__get__("decrypt").call(fle, response);

      assert.ok(JSON.stringify(body) === JSON.stringify(decrypted));
    });

  });

  describe("#decrypt", () => {
    const fle = new FieldLevelEncryption(testConfig);
    const decrypt = FieldLevelEncryption.__get__("decrypt");

    it("decrypt response", () => {
      const response = require("./mock/response");
      const res = decrypt.call(fle, response);
      assert.ok(res.foo.accountNumber === "5123456789012345");
      assert.ok(!res.foo.elem1);
      assert.ok(!Object.prototype.hasOwnProperty.call(res.foo, 'encryptedData'));
    });

    it("decrypt response with readme config", () => {
      const testConfigReadme = require("./mock/config-readme");
      const fle = new FieldLevelEncryption(testConfigReadme);
      const decrypt = FieldLevelEncryption.__get__("decrypt");
      const responseReadme = require("./mock/response-readme");
      const res = decrypt.call(fle, responseReadme);
      assert(res.path);
      assert(res.path.to);
      assert(res.path.to.foo);
      assert(res.path.to.foo.sensitive);
      assert(res.path.to.foo.sensitive2);
    });

    it("decrypt response with no valid config", () => {
      const response = JSON.parse(JSON.stringify(require("./mock/response")));
      delete response.body.elem1;
      const res = decrypt.call(fle, response);
      assert.ok(res === response.body);
    });

    it("decrypt response replacing whole body", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.paths[0].toDecrypt[0].element = "";
      config.paths[0].toDecrypt[0].obj = "encryptedData";
      const fle = new FieldLevelEncryption(config);
      const response = require("./mock/response-root");
      const res = decrypt.call(fle, response);
      assert.ok(res.encryptedData.accountNumber === "5123456789012345");
      assert.ok(res.notDelete);
    });

    it("decrypt with header", () => {
      const response = require("./mock/response-header");
      const headerConfig = require("./mock/config-header");
      const fle = new FieldLevelEncryption(headerConfig);
      const decrypt = FieldLevelEncryption.__get__("decrypt");
      const res = decrypt.call(fle, response);
      assert.ok(res.accountNumber === "5123456789012345");
    });

    it("decrypt with header when node not found in body", () => {
      const response = require("./mock/response-header");
      const headerConfig = require("./mock/config-header");
      const fle = new FieldLevelEncryption(headerConfig);
      const decrypt = FieldLevelEncryption.__get__("decrypt");
      delete response.body.encrypted_payload;
      response.body = {test: "foo"};
      const res = decrypt.call(fle, response);
      assert.ok(JSON.stringify(res) === JSON.stringify({test: "foo"}));
    });

    it("decrypt without config", () => {
      const fle = new FieldLevelEncryption(testConfig);
      const response = {request: {url: "/foobar"}, body: "body"};
      const res = decrypt.call(fle, response);
      assert.ok(res === "body");
    });

    it("decrypt root arrays", () => {
      const response = {
        request: {url: "/array-resp"},
        body: {
          encryptedData:
            '3496b0c505bcea6a849f8e30b553e6d4',
          iv: 'ed82c0496e9d5ac769d77bdb2eb27958',
          encryptedKey:
            '29ea447b70bdf85dd509b5d4a23dc0ffb29fd1acf50ed0800ec189fbcf1fb813fa075952c3de2915d63ab42f16be2ed46dc27ba289d692778a1d585b589039ba0b25bad326d699c45f6d3cffd77b5ec37fe12e2c5456d49980b2ccf16402e83a8e9765b9b93ca37d4d5181ec3e5327fd58387bc539238f1c20a8bc9f4174f5d032982a59726b3e0b9cf6011d4d7bfc3afaf617e768dea6762750bce07339e3e55fdbd1a1cd12ee6bbfbc3c7a2d7f4e1313410eb0dad13e594a50a842ee1b2d0ff59d641987c417deaa151d679bc892e5c051b48781dbdefe74a12eb2b604b981e0be32ab81d01797117a24fbf6544850eed9b4aefad0eea7b3f5747b20f65d3f',
          oaepHashingAlgorithm: 'SHA256'
        }
      };
      const fle = new FieldLevelEncryption(testConfig);
      const res = decrypt.call(fle, response);
      assert.ok(res instanceof Array);
      assert.ok(JSON.stringify(res) === "[{},{}]");
    });

    it("decrypt root arrays to path", () => {
      const response = {
        request: {url: "/array-resp2"},
        body: {
          encryptedData:
            '3496b0c505bcea6a849f8e30b553e6d4',
          iv: 'ed82c0496e9d5ac769d77bdb2eb27958',
          encryptedKey:
            '29ea447b70bdf85dd509b5d4a23dc0ffb29fd1acf50ed0800ec189fbcf1fb813fa075952c3de2915d63ab42f16be2ed46dc27ba289d692778a1d585b589039ba0b25bad326d699c45f6d3cffd77b5ec37fe12e2c5456d49980b2ccf16402e83a8e9765b9b93ca37d4d5181ec3e5327fd58387bc539238f1c20a8bc9f4174f5d032982a59726b3e0b9cf6011d4d7bfc3afaf617e768dea6762750bce07339e3e55fdbd1a1cd12ee6bbfbc3c7a2d7f4e1313410eb0dad13e594a50a842ee1b2d0ff59d641987c417deaa151d679bc892e5c051b48781dbdefe74a12eb2b604b981e0be32ab81d01797117a24fbf6544850eed9b4aefad0eea7b3f5747b20f65d3f',
          oaepHashingAlgorithm: 'SHA256'
        }
      };
      const fle = new FieldLevelEncryption(testConfig);
      const res = decrypt.call(fle, response);
      assert.ok(res instanceof Object);
      assert.ok(JSON.stringify(res) === "{\"path\":{\"to\":{\"foo\":[{},{}]}}}");
    });

  });

  describe("#setHeader", () => {
    const headerConfig = require("./mock/config-header");
    const fle = new FieldLevelEncryption(headerConfig);
    const setHeader = FieldLevelEncryption.__get__("setHeader");

    it("set http header from config", () => {
      const header = {};
      const params = {
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
      const FieldLevelEncryption = require("..").FieldLevelEncryption;
      assert.ok(FieldLevelEncryption);
      const fle = new FieldLevelEncryption(testConfig);
      assert.ok(fle.crypto);
    });
  });

});
