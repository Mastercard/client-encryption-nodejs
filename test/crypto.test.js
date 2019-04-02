const assert = require('assert');
const rewire = require('rewire');
const Crypto = rewire("../lib/mcapi/crypto/crypto");
const utils = require("../lib/mcapi/utils/utils");

const testConfig = require("./mock/config");
const testConfigHeader = require("./mock/config-header");

const iv = "6f38f3ecd8b92c2fd2537a7235deb9a8";
const secretKey = "bab78b5ec588274a4dd2a60834efcf60";

describe("Crypto", () => {

  describe("#new Crypto", () => {
    it("with empty config", () => {
      assert.throws(() =>
        new Crypto({}), Error("Config not valid: paths should be an array of path element.")
      );
    });

    it("with string config", () => {
      assert.throws(() =>
        new Crypto(""), Error("Config not valid: config should be an object.")
      );
    });

    it("with wrong encoding", () => {
      let config = JSON.parse(JSON.stringify(testConfig));
      config["dataEncoding"] = "foo";
      assert.throws(() =>
        new Crypto(config), Error("Config not valid: dataEncoding should be 'hex' or 'base64'")
      );
    });

    it("with one property not defined", () => {
      let config = JSON.parse(JSON.stringify(testConfig));
      delete config["ivFieldName"];
      assert.throws(() =>
        new Crypto(config), Error("Config not valid: please check that all the properties are defined.")
      );
    });

    it("with empty paths", () => {
      let config = JSON.parse(JSON.stringify(testConfig));
      config.paths = [];
      assert.throws(() =>
        new Crypto(config), Error("Config not valid: paths should be not empty.")
      );
    });

    it("with valid config", () => {
      assert.doesNotThrow(() =>
        new Crypto(testConfig)
      );
    });


    it("with valid config with private keystore", () => {
      assert.doesNotThrow(() => {
          let config = JSON.parse(JSON.stringify(testConfig));
          delete config.privateKey;
          config.keyStore = "./test/res/test_key.p12";
          config.keyStoreAlias = "mykeyalias";
          config.keyStorePassword = "Password1";
          new Crypto(config);
        }
      );
    });

    it("with valid config header", () => {
      assert.doesNotThrow(() =>
        new Crypto(testConfigHeader)
      );
    });

    it("with config header missing iv", () => {
      let config = JSON.parse(JSON.stringify(testConfigHeader));
      delete config["ivHeaderName"];
      assert.throws(() =>
        new Crypto(config), Error("Config not valid: please check that all the properties are defined.")
      );
    });
  });

  describe("#encryptData()", () => {
    let crypto;
    before(() => {
      crypto = new Crypto(testConfig);
    });

    it("with empty string", () => {
      assert.throws(() => {
        crypto.encryptData({data: ""});
      }, Error("Json not valid"));
    });

    it("with valid object, iv and secretKey", () => {
      let data = JSON.stringify({text: "message"});
      let resp = crypto.encryptData({
        data: data,
        iv: utils.stringToBytes(iv, 'hex'),
        secretKey: utils.stringToBytes(secretKey, 'hex')
      });
      assert.ok(resp.encryptedData === "3590b63d1520a57bd4cd1414a7a75f47d65f99e1427d6cfe744d72ee60f2b232");
      assert.ok(resp.publicKeyFingerprint === "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279");
    });

    it("with valid object", () => {
      let data = JSON.stringify({text: "message"});
      let resp = crypto.encryptData({
        data: data
      });
      assert.ok(resp);
      assert.ok(resp.encryptedKey);
      assert.ok(resp.encryptedData);
      assert.ok(resp.iv);
      assert.ok(resp.oaepHashingAlgorithm);
    });
  });

  describe("#decryptData()", () => {
    let crypto;
    before(() => {
      crypto = new Crypto(testConfig);
    });

    it("with null", () => {
      assert.throws(() => {
        crypto.decryptData(null);
      }, Error("Input not valid"));
    });

    it("with empty string", () => {
      assert.throws(() => {
        crypto.decryptData("");
      }, Error("Input not valid"));
    });

    it("with valid object", () => {
      let resp = crypto.decryptData("3590b63d1520a57bd4cd1414a7a75f47d65f99e1427d6cfe744d72ee60f2b232", iv, "SHA-512",
        "e283a661efa235fbc5e7243b7b78914a7f33574eb66cc1854829f7debfce4163f3ce86ad2c3ed2c8fe97b2258ab8a158281147698b7fddf5e82544b0b637353d2c204798f014112a5e278db0b29ad852b1417dc761593fad3f0a1771797771796dc1e8ae916adaf3f4486aa79af9d4028bc8d17399d50c80667ea73a8a5d1341a9160f9422aaeb0b4667f345ea637ac993e80a452cb8341468483b7443f764967264aaebb2cad4513e4922d076a094afebcf1c71b53ba3cfedb736fa2ca5de5c1e2aa88b781d30c27debd28c2f5d83e89107d5214e3bb3fe186412d78cefe951e384f236e55cd3a67fb13c0d6950f097453f76e7679143bd4e62d986ce9dc770");
      assert.ok(JSON.stringify(resp) === JSON.stringify({text: "message"}));
    });

  });

  describe("#generateSecretKey", () => {
    it("not valid algorithm", () => {
      let generateSecretKey = Crypto.__get__("generateSecretKey");
      assert.throws(() => {
        generateSecretKey("ABC");
      }, Error("Unsupported symmetric algorithm"));
    });
  });

  describe("#loadPrivateKey", () => {
    it("not valid key", () => {
      let loadPrivateKey = Crypto.__get__("loadPrivateKey");
      assert.throws(() => {
        loadPrivateKey("./test/res/empty.key");
      }, Error("Private key content not valid"));
    });
  });

  describe("#readPublicCertificate", () => {
    it("not valid key", () => {
      let readPublicCertificate = Crypto.__get__("readPublicCertificate");
      assert.throws(() => {
        readPublicCertificate("./test/res/empty.key");
      }, Error("Public certificate content is not valid"));
    });
  });

  describe("#getPrivateKey", () => {
    let getPrivateKey = Crypto.__get__("getPrivateKey");

    it("not valid key", () => {
      assert.throws(() => {
        getPrivateKey("./test/res/empty.key");
      }, Error("p12 keystore content is empty"));
    });

    it("empty alias", () => {
      assert.throws(() => {
        getPrivateKey("./test/res/test_key_container.p12");
      }, Error("Key alias is not set"));
    });

    it("empty password", () => {
      assert.throws(() => {
        getPrivateKey("./test/res/test_key_container.p12", "keyalias");
      }, Error("Keystore password is not set"));
    });

    it("valid p12", () => {
      let pk = getPrivateKey("./test/res/test_key_container.p12", "mykeyalias", "Password1");
      assert.ok(pk);
    });

    it("valid p12, alias not found", () => {
      assert.throws(() => {
        getPrivateKey("./test/res/test_key_container.p12", "mykeyalias1", "Password1");
      }, Error("No key found for alias [mykeyalias1]"));
    });
  });

});
