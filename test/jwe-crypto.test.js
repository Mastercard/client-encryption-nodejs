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

    it("encrypt primitive string", () => {
      const data = "message";
      let resp = crypto.encryptData({
        data: data,
      });
      resp = resp[testConfig.encryptedValueFieldName].split(".");
      assert.ok(resp.length === 5);
      //Header is always constant
      assert.strictEqual(
        resp[0],
        "eyJraWQiOiJnSUVQd1RxREdmenc0dXd5TElLa3d3UzNnc3c4NW5FWFkwUFA2QllNSW5rPSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24iLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
      );
      assert.ok(resp[1].length === 342);
      assert.ok(resp[2].length === 22);
      assert.ok(resp[3].length === 10);
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

    it("with valid AES128GCM object", () => {
      const resp = crypto.decryptData(
        "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.WtvYljbsjdEv-Ttxx1p6PgyIrOsLpj1FMF9NQNhJUAHlKchAo5QImgEgIdgJE7HC2KfpNcHiQVqKKZq_y201FVzpicDkNzlPJr5kIH4Lq-oC5iP0agWeou9yK5vIxFRP__F_B8HSuojBJ3gDYT_KdYffUIHkm_UysNj4PW2RIRlafJ6RKYanVzk74EoKZRG7MIr3pTU6LIkeQUW41qYG8hz6DbGBOh79Nkmq7Oceg0ZwCn1_MruerP-b15SGFkuvOshStT5JJp7OOq82gNAOkMl4fylEj2-vADjP7VSK8GlqrA7u9Tn-a4Q28oy0GOKr1Z-HJgn_CElknwkUTYsWbg.PKl6_kvZ4_4MjmjW.AH6pGFkn7J49hBQcwg.zdyD73TcuveImOy4CRnVpw"
      );
      assert.ok(JSON.stringify(resp) === JSON.stringify({ foo: "bar" }));
    });

    it("with valid AES192GCM object", () => {
      const resp = crypto.decryptData(
        "eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.FWC8PVaZoR2TRKwKO4syhSJReezVIvtkxU_yKh4qODNvlVr8t8ttvySJ-AjM8xdI6vNyIg9jBMWASG4cE49jT9FYuQ72fP4R-Td4vX8wpB8GonQj40yLqZyfRLDrMgPR20RcQDW2ThzLXsgI55B5l5fpwQ9Nhmx8irGifrFWOcJ_k1dUSBdlsHsYxkjRKMENu5x4H6h12gGZ21aZSPtwAj9msMYnKLdiUbdGmGG_P8a6gPzc9ih20McxZk8fHzXKujjukr_1p5OO4o1N4d3qa-YI8Sns2fPtf7xPHnwi1wipmCC6ThFLU80r3173RXcpyZkF8Y3UacOS9y1f8eUfVQ.JRE7kZLN4Im1Rtdb.eW_lJ-U330n0QHqZnQ._r5xYVvMCrvICwLz4chjdw"
      );
      assert.ok(JSON.stringify(resp) === JSON.stringify({ foo: "bar" }));
    });

    it("with valid AES256GCM object", () => {
      const resp = crypto.decryptData(
          "eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA"
      );
      assert.ok(JSON.stringify(resp) === JSON.stringify({ foo: "bar" }));
    });

    it("with valid encrypted string", () => {
      const resp = crypto.decryptData(
        "eyJraWQiOiJnSUVQd1RxREdmenc0dXd5TElLa3d3UzNnc3c4NW5FWFkwUFA2QllNSW5rPSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24iLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.vZBAXJC5Xcr0LaxdTRooLrbKc0B2cqjqAv3Dfz70s2EdUHf-swWPFe6QE-gb8PW7PQ-PZxkkIE5MhP6IMH4e/NH79V5j27c6Tno3R1/DfWQjRoN8xNm4sZver4FXESBiQia-PZip4D/hVmDWLKbom4SCD6ibLLmB9WcDVXpQEmX5G-lmd6kuEoBNOKQy08/QfVhqEr2H/2Q7PAcOjizPWUw6QK0SYzkaQIgTC6nlN/swa82zZa9NJeeTxJ1sJVmXzd4J-qjxwWjtzuRqb-kh4t/CUYT/lpf5NRaktBjXFyZFJ1dir5OgfdoA6-oIh8oUNMCt26SCCuYg-ev8sfHGDA.rxP1lOVCy4hIDwi5ETr2Bw.a3IIS9/6lA.77pOElwKjHBEwaPgRfHI4w"
      );
      assert.strictEqual(resp, "message");
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

    it("compute public fingerprint: defaults to publicKey with publicKeyFingerprintType set", () => {
      const strippedConfig = JSON.parse(JSON.stringify(testConfig));
      delete strippedConfig["publicKeyFingerprintType"];
      delete strippedConfig["dataEncoding"];

      assert.ok(
        "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
        computePublicFingerprint.call(crypto, {
          strippedConfig
        })
      );
    });
  });
});
