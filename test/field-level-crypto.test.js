const assert = require('assert');
const rewire = require('rewire');
const Crypto = rewire("../lib/mcapi/crypto/field-level-crypto");
const utils = require("../lib/mcapi/utils/utils");

const testConfig = require("./mock/config");
const testConfigHeader = require("./mock/config-header");

const iv = "6f38f3ecd8b92c2fd2537a7235deb9a8";
const secretKey = "bab78b5ec588274a4dd2a60834efcf60";

describe("Field Level Crypto", () => {

  describe("#new Crypto", () => {
    it("with empty config", () => {
      assert.throws(() =>
        new Crypto({}), /Config not valid: paths should be an array of path element./
      );
    });

    it("with string config", () => {
      assert.throws(() =>
        new Crypto(""), /Config not valid: config should be an object./
      );
    });

    it("with wrong encoding", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config["dataEncoding"] = "foo";
      assert.throws(() =>
        new Crypto(config), /Config not valid: dataEncoding should be 'hex' or 'base64'/
      );
    });

    it("with one property not defined", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config["ivFieldName"];
      assert.throws(() =>
        new Crypto(config), /Config not valid: please check that all the properties are defined./
      );
    });

    it("with empty paths", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.paths = [];
      assert.throws(() =>
        new Crypto(config), /Config not valid: paths should be not empty./
      );
    });

    it("with valid config", () => {
      assert.doesNotThrow(() =>
        new Crypto(testConfig)
      );
    });

    it("with valid config with private keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs12/test_key.p12";
      config.keyStoreAlias = "mykeyalias";
      config.keyStorePassword = "Password1";
      assert.doesNotThrow(() => {
          new Crypto(config);
        }
      );
    });

    it("with valid config with private pkcs1 pem keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs1/test_key.pem";
      assert.doesNotThrow(() => {
          new Crypto(config);
        }
      );
    });

    it("with valid config with private pkcs8 pem keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs8/test_key.pem";
      assert.doesNotThrow(() => {
          new Crypto(config);
        }
      );
    });

    it("with valid config with private pkcs8 der keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs8/test_key.der";
      assert.doesNotThrow(() => {
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
      const config = JSON.parse(JSON.stringify(testConfigHeader));
      delete config["ivHeaderName"];
      assert.throws(() =>
        new Crypto(config), /Config not valid: please check that all the properties are defined./
      );
    });

    it("without publicKeyFingerprintType", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config["publicKeyFingerprintType"];
      assert.throws(() => new Crypto(config), /Config not valid: propertiesFingerprint should be: 'certificate' or 'publicKey'/);
    });

    it("without publicKeyFingerprintType, but providing the publicKeyFingerprint", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config["publicKeyFingerprintType"];
      config.publicKeyFingerprint = "abc";
      assert.ok(new Crypto(config).publicKeyFingerprint = "abc");
    });

    it("with wrong publicKeyFingerprintType", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.publicKeyFingerprintType = "foobar";
      assert.throws(() => new Crypto(config), /Config not valid: propertiesFingerprint should be: 'certificate' or 'publicKey'/);
    });

    it("with right publicKeyFingerprintType: certificate", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.publicKeyFingerprintType = "certificate";
      assert.doesNotThrow(() => new Crypto(config));
    });

    it("with right publicKeyFingerprintType: publicKey", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.publicKeyFingerprintType = "publicKey";
      assert.doesNotThrow(() => new Crypto(config));
    });

    it("without keyStore and privateKey", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config["privateKey"];
      delete config["keyStore"];
      assert.doesNotThrow(() => new Crypto(config));
    });

    it("with multiple roots (encrypt)", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.paths[2].toEncrypt.push(config.paths[2].toEncrypt[0]);
      assert.throws(() => new Crypto(config), /Config not valid: found multiple configurations encrypt\/decrypt with root mapping/);
    });

    it("with multiple roots (decrypt)", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.paths[2].toDecrypt.push(config.paths[2].toDecrypt[0]);
      config.paths[2].toDecrypt[1].obj = "abc";
      assert.throws(() => new Crypto(config), /Config not valid: found multiple configurations encrypt\/decrypt with root mapping/);
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
      }, /Json not valid/);
    });

    it("with valid object, iv and secretKey", () => {
      const data = JSON.stringify({text: "message"});
      const resp = crypto.encryptData({
        data: data,
        iv: utils.stringToBytes(iv, 'hex'),
        secretKey: utils.stringToBytes(secretKey, 'hex')
      });
      assert.ok(resp.encryptedData === "3590b63d1520a57bd4cd1414a7a75f47d65f99e1427d6cfe744d72ee60f2b232");
      assert.ok(resp.publicKeyFingerprint === "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279");
    });

    it("without publicKeyFingerprint", () => {
      const crypto = new Crypto(testConfig);
      crypto.publicKeyFingerprint = null;
      const data = JSON.stringify({text: "message"});
      const resp = crypto.encryptData({
        data: data
      });
      assert.ok(resp);
      assert.ok(!resp.publicKeyFingerprint);
    });

    it("with valid object", () => {
      const data = JSON.stringify({text: "message"});
      const resp = crypto.encryptData({
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
      }, /Input not valid/);
    });

    it("with empty string", () => {
      assert.throws(() => {
        crypto.decryptData("");
      }, /Input not valid/);
    });

    it("with valid object", () => {
      const resp = crypto.decryptData("3590b63d1520a57bd4cd1414a7a75f47d65f99e1427d6cfe744d72ee60f2b232", iv, "SHA-512",
        "e283a661efa235fbc5e7243b7b78914a7f33574eb66cc1854829f7debfce4163f3ce86ad2c3ed2c8fe97b2258ab8a158281147698b7fddf5e82544b0b637353d2c204798f014112a5e278db0b29ad852b1417dc761593fad3f0a1771797771796dc1e8ae916adaf3f4486aa79af9d4028bc8d17399d50c80667ea73a8a5d1341a9160f9422aaeb0b4667f345ea637ac993e80a452cb8341468483b7443f764967264aaebb2cad4513e4922d076a094afebcf1c71b53ba3cfedb736fa2ca5de5c1e2aa88b781d30c27debd28c2f5d83e89107d5214e3bb3fe186412d78cefe951e384f236e55cd3a67fb13c0d6950f097453f76e7679143bd4e62d986ce9dc770");
      assert.ok(JSON.stringify(resp) === JSON.stringify({text: "message"}));
    });

  });

  describe("#generateSecretKey", () => {
    it("not valid algorithm", () => {
      const generateSecretKey = Crypto.__get__("generateSecretKey");
      assert.throws(() => {
        generateSecretKey("ABC");
      }, /Unsupported symmetric algorithm/);
    });
  });

  describe("#newEncryptionParams", () => {
    let crypto;
    before(() => {
      crypto = new Crypto(testConfig);
    });
    it("without options", () => {
      const params = crypto.newEncryptionParams();
      assert.ok(params.iv);
      assert.ok(params.secretKey);
      assert.ok(params.encryptedKey);
      assert.ok(params.oaepHashingAlgorithm);
      assert.ok(params.publicKeyFingerprint);
      assert.ok(params.encoded);
      assert.ok(params.encoded.iv);
      assert.ok(params.encoded.secretKey);
      assert.ok(params.encoded.encryptedKey);
    });
  });

  describe("#createOAEPOptions", () => {
    const createOAEPOptions = Crypto.__get__("createOAEPOptions");

    it("not valid asymmetricCipher", () => {
      assert.ok(!createOAEPOptions("foobar"));
    });

    it("valid asymmetricCipher and oaepHashingAlgorithm", () => {
      const opts = createOAEPOptions("OAEP", "SHA-256");
      assert.ok(opts.md);
      assert.ok(opts.mgf1);
    });
  });

});
