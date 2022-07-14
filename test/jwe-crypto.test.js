const assert = require("assert");
const rewire = require("rewire");
const Crypto = rewire("../lib/mcapi/crypto/jwe-crypto");
const utils = require("../lib/mcapi/utils/utils");

const testConfig = require("./mock/jwe-config");

describe("JWE Crypto", () => {
  before(function () {
    if (!utils.nodeVersionSupportsJWE()) {
      this.skip();
    }
  });

  describe("#new Crypto", () => {
    it("with empty config", () => {
      assert.throws(
        () => new Crypto({}),
        /Config not valid: paths should be an array of path element./
      );
    });

    it("with string config", () => {
      assert.throws(
        () => new Crypto(""),
        /Config not valid: config should be an object./
      );
    });

    it("with one property not defined", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config["encryptionCertificate"];
      assert.throws(
        () => new Crypto(config),
        /Config not valid: please check that all the properties are defined./
      );
    });

    it("with empty paths", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.paths = [];
      assert.throws(
        () => new Crypto(config),
        /Config not valid: paths should be not empty./
      );
    });

    it("with valid config", () => {
      assert.doesNotThrow(() => new Crypto(testConfig));
    });

    it("with valid config with private keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs12/test_key.p12";
      config.keyStoreAlias = "mykeyalias";
      config.keyStorePassword = "Password1";
      assert.doesNotThrow(() => {
        new Crypto(config);
      });
    });

    it("with valid config with private pkcs1 pem keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs1/test_key.pem";
      assert.doesNotThrow(() => {
        new Crypto(config);
      });
    });

    it("with valid config with private pkcs8 pem keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs8/test_key.pem";
      assert.doesNotThrow(() => {
        new Crypto(config);
      });
    });

    it("with valid config with private pkcs8 der keystore", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config.privateKey;
      config.keyStore = "./test/res/keys/pkcs8/test_key.der";
      assert.doesNotThrow(() => {
        new Crypto(config);
      });
    });

    it("without publicKeyFingerprintType", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config["publicKeyFingerprintType"];
      assert.throws(
        () => new Crypto(config),
        /Config not valid: publicKeyFingerprintType should be: 'certificate' or 'publicKey'/
      );
    });

    it("without publicKeyFingerprintType, but providing the publicKeyFingerprint", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      delete config["publicKeyFingerprintType"];
      config.publicKeyFingerprint = "abc";
      assert.ok((new Crypto(config).publicKeyFingerprint = "abc"));
    });

    it("with wrong publicKeyFingerprintType", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.publicKeyFingerprintType = "foobar";
      assert.throws(
        () => new Crypto(config),
        /Config not valid: publicKeyFingerprintType should be: 'certificate' or 'publicKey'/
      );
    });

    it("with right publicKeyFingerprintType: certificate and dataEncoding: base64", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.publicKeyFingerprintType = "certificate";
      config.dataEncoding = "base64";
      assert.doesNotThrow(() => new Crypto(config));
    });

    it("with right publicKeyFingerprintType: certificate and dataEncoding: hex", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.publicKeyFingerprintType = "certificate";
      config.dataEncoding = "hex";
      assert.doesNotThrow(() => new Crypto(config));
    });

    it("with right publicKeyFingerprintType: certificate and dataEncoding: null", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.publicKeyFingerprintType = "certificate";
      delete config["dataEncoding"];
      assert.throws(
        () => new Crypto(config),
        /Config not valid: if publicKeyFingerprintType is 'certificate' dataEncoding must be either 'base64' or 'hex'/
      );
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
      assert.throws(
        () => new Crypto(config),
        /Config not valid: found multiple configurations encrypt\/decrypt with root mapping/
      );
    });

    it("with multiple roots (decrypt)", () => {
      const config = JSON.parse(JSON.stringify(testConfig));
      config.paths[2].toDecrypt.push(config.paths[2].toDecrypt[0]);
      config.paths[2].toDecrypt[1].obj = "abc";
      assert.throws(
        () => new Crypto(config),
        /Config not valid: found multiple configurations encrypt\/decrypt with root mapping/
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
        crypto.encryptData({ data: "" });
      }, /Json not valid/);
    });

    it("with valid config", () => {
      const data = JSON.stringify({ text: "message" });
      let resp = crypto.encryptData({
        data: data,
      });
      resp = resp[testConfig.encryptedValueFieldName].split(".");
      assert.ok(resp.length === 5);
      //Header is always constant
      assert.ok(
        resp[0] ===
          "eyJraWQiOiJnSUVQd1RxREdmenc0dXd5TElLa3d3UzNnc3c4NW5FWFkwUFA2QllNSW5rPSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24iLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
      );
      assert.ok(resp[1].length === 342);
      assert.ok(resp[2].length === 22);
      assert.ok(resp[3].length === 24);
      assert.ok(resp[4].length === 22);
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
      const resp = crypto.decryptData(
        "eyJraWQiOiJnSUVQd1RxREdmenc0dXd5TElLa3d3UzNnc3c4NW5FWFkwUFA2QllNSW5rPSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24iLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.SVXykIq7DXb7XxJir8t9FpHNXdpW4sgeRcFX6lMGMPln42tqV3XOEivab3MLFPBp1ZKEV_BsClwVipktyMRsJxaBgmzPHgV9mplR_jD80zGIR9DcJT6Q69rVUdcFymqEpaAGWMq0Ho4Nz2mF0lqd_30DrR7DJ5H_uZ5PlYbBbqE2NRdMn2KAveZ6SHMF4NEUXMeXRZ5X2ZLQslEUz6ShhYBBUaJvLSMrzvxXU8sZ1oWbK66eN53fqsFBN-eXh9hpUtTf1mtXBYmZXE22Mwn_UVCjoGEh1FBhndbcvfnGoI20SrGMQken7HfqvIezNjDbl60ROUQRZSKZMJx89s3pdw.v2WNe6a_InN2-3NDGLJ07Q.JOSJctFh19WmAAClGVK2VI0d.0mvaxcRBa1bHFq6Bw58cIw"
      );
      assert.ok(JSON.stringify(resp) === JSON.stringify({ text: "message" }));
    });
  });

  describe("#readPublicCertificate", () => {
    it("not valid key", () => {
      const readPublicCertificate = Crypto.__get__("readPublicCertificate");
      assert.throws(() => {
        readPublicCertificate("./test/res/empty.key");
      }, /Public certificate content is not valid/);
    });
  });

  describe("#computePublicFingerprint", () => {
    const computePublicFingerprint = Crypto.__get__("computePublicFingerprint");
    let crypto;
    before(() => {
      crypto = new Crypto(testConfig);
    });

    it("not valid config", () => {
      assert.ok(!computePublicFingerprint());
    });

    it("not valid publicKeyFingerprintType", () => {
      assert.ok(!computePublicFingerprint({}));
    });

    it("compute public fingerprint: certificate", () => {
      assert.ok(
        "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
        computePublicFingerprint.call(crypto, {
          publicKeyFingerprintType: "certificate",
        })
      );
    });

    it("compute public fingerprint: publicKey", () => {
      assert.ok(
        "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
        computePublicFingerprint.call(crypto, {
          publicKeyFingerprintType: "publicKey",
        })
      );
    });
  });
});
