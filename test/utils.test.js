const assert = require("assert");
const utils = require("../lib/mcapi/utils/utils");
const testConfig = require("./mock/config");

describe("Utils", () => {
  describe("#isSet", () => {
    it("when null", () => {
      assert.ok(utils.isSet(null) === false);
    });

    it("when undefined", () => {
      assert.ok(utils.isSet(undefined) === false);
    });

    it("when obj defined", () => {
      assert.ok(utils.isSet({}) === true);
    });

    it("when string defined and empty", () => {
      assert.ok(utils.isSet("") === false);
    });

    it("when string defined and not empty", () => {
      assert.ok(utils.isSet("not empty") === true);
    });
  });

  describe("#bytesToString", () => {
    it("when null", () => {
      assert.throws(() => {
        utils.bytesToString(null, "hex");
      });
    });

    it("when undefined", () => {
      assert.throws(() => {
        utils.bytesToString(undefined, "hex");
      });
    });

    it("when empty obj", () => {
      const res = utils.bytesToString({}, "hex");
      assert.ok(res === "");
    });

    it("when empty str", () => {
      const res = utils.bytesToString("", "hex");
      assert.ok(res === "");
    });

    it("when wrong encoding", () => {
      const res = utils.bytesToString("abc", "XXX");
      assert.ok(res === "YWJj"); // default is base64
    });

    it("when test str hex", () => {
      const res = utils.bytesToString("test", "hex");
      assert.ok(res === "74657374");
    });

    it("when test str base64", () => {
      const res = utils.bytesToString("test", "base64");
      assert.ok(res === "dGVzdA==");
    });
  });

  describe("#stringToBytes", () => {
    it("when null", () => {
      assert.throws(() => {
        utils.stringToBytes(null, "hex");
      });
    });

    it("when undefined", () => {
      assert.throws(() => {
        utils.stringToBytes(undefined, "hex");
      });
    });

    it("when empty obj", () => {
      const res = utils.stringToBytes({}, "hex");
      assert.ok(res === "");
    });

    it("when empty str", () => {
      const res = utils.stringToBytes("", "hex");
      assert.ok(res === "");
    });

    it("when wrong encoding", () => {
      const res = utils.stringToBytes("dGVzdGluZ3V0aWxz", "XXX");
      assert.ok(res === "testingutils");
    });

    it("when test str hex", () => {
      const res = utils.stringToBytes("74657374696E677574696C73", "hex");
      assert.ok(res === "testingutils");
    });

    it("when test str base64", () => {
      const res = utils.stringToBytes("dGVzdGluZ3V0aWxz", "base64");
      assert.ok(res === "testingutils");
    });

    it("encoding and decoding base64", () => {
      const str = "dGVzdGluZ3V0aWxz";
      const res = utils.stringToBytes(str, "base64");
      assert.ok(utils.bytesToString(res, "base64") === str);
    });
  });

  describe("#jsonToString", () => {
    it("when null", () => {
      assert.throws(() => {
        utils.jsonToString(null);
      });
    });

    it("when undefined", () => {
      assert.throws(() => {
        utils.jsonToString(undefined);
      });
    });

    it("when empty obj", () => {
      const res = utils.jsonToString({});
      assert.ok(res === "{}");
    });

    it("when empty str", () => {
      assert.throws(() => utils.jsonToString(""));
    });

    it("correct json from object", () => {
      const res = utils.jsonToString({ field: "value" });
      assert.strictEqual(res, '{"field":"value"}');
    });

    it("correct json from string", () => {
      const res = utils.jsonToString('{"field": "value"}');
      assert.strictEqual(res, '{"field":"value"}');
    });

    it("string from string", () => {
      const res = utils.jsonToString('value');
      assert.strictEqual(res, 'value');
    });

    it("string from string object", () => {
      const res = utils.jsonToString(new String("value"));
      assert.strictEqual(res, 'value');
    });
  });

  describe("#stringToJson", () => {
    it("when null", () => {
      assert.throws(() => {
        utils.stringToJson(null);
      });
    });

    it("when undefined", () => {
      assert.throws(() => {
        utils.stringToJson(undefined);
      });
    });

    it("when empty obj", () => {
      const res = utils.stringToJson('{}');
      assert.strictEqual(JSON.stringify(res), JSON.stringify({}));
    });

    it("when empty str", () => {
      assert.throws(() => utils.stringToJson(""));
    });

    it("when Json object", () => {
      assert.throws(() => utils.stringToJson({ field: "value" }));
    });

    it("string from string", () => {
      const res = utils.stringToJson('value');
      assert.strictEqual(res, "value");
    });

    it("string from string object", () => {
      const res = utils.stringToJson(new String("value"));
      assert.strictEqual(res, "value");
    });

    it("correct json object from string", () => {
      const res = utils.stringToJson('{"field": "value"}');
      assert.strictEqual(JSON.stringify(res), JSON.stringify({ field: 'value' }));
    });
  });

  describe("#mutateObjectProperty", () => {
    it("change object value", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value",
            },
          },
        },
      };
      const path = "first.second.third";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(obj.first.second.third === "changed");
    });

    it("change object value, change it but not delete", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value",
            },
          },
        },
      };
      const path = "first.second.third";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(obj.first.second.third === "changed");
    });

    it("field not found, create it", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value",
            },
          },
        },
      };
      const objStr = JSON.stringify({
        first: { second: { third: { field: "value" }, not_exists: "changed" } },
      });
      const path = "first.second.not_exists";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

    it("field not found, create it, long path", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value",
            },
          },
        },
      };
      const objStr = JSON.stringify({
        first: {
          second: {
            third: {
              field: "value",
            },
          },
        },
        foo: {
          bar: {
            yet: {
              another: {
                foo: {
                  bar: "changed",
                },
              },
            },
          },
        },
      });
      const path = "foo.bar.yet.another.foo.bar";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

    it("first part of path is correct, but field not found, create it", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value",
            },
          },
        },
      };
      const objStr = JSON.stringify({
        first: {
          second: {
            third: {
              field: "value",
            },
          },
          foo: {
            third: "changed",
          },
        },
      });
      const path = "first.foo.third";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

    it("path is null", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value",
            },
          },
        },
      };
      const objStr = JSON.stringify(obj);
      utils.mutateObjectProperty(null, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });
  });

  describe("#deleteNode", () => {
    it("with nulls", () => {
      assert.doesNotThrow(() => {
        utils.deleteNode(null, null, null);
        utils.deleteNode("path.to.foo", null, null);
        const body = {};
        utils.deleteNode("path.to.foo", body);
        assert.ok(JSON.stringify(body) === JSON.stringify({}));
      });
    });

    it("not found path, shouldn't remove it", () => {
      const body = { path: { to: { foo: { field: "value" } } } };
      const str = JSON.stringify(body);
      utils.deleteNode("path.to.notfound", body, null);
      assert.ok(str === JSON.stringify(body));
    });

    it("path found, should remove it", () => {
      const body = { path: { to: { foo: { field: "value" } } } };
      utils.deleteNode("path.to.foo", body, null);
      assert.ok(JSON.stringify({ path: { to: {} } }) === JSON.stringify(body));
    });

    it("root path, without properties, shouldn't remove", () => {
      const body = { path: { to: { foo: { field: "value" } } } };
      const str = JSON.stringify(body);
      utils.deleteNode("", body, null);
      assert.ok(str === JSON.stringify(body));
    });

    it("root path, with properties, should remove the properties", () => {
      const body = {
        path: { to: { foo: { field: "value" } } },
        prop: "prop",
        prop2: "prop2",
      };
      utils.deleteNode("", body, ["prop", "prop2"]);
      assert.ok(
        JSON.stringify({ path: { to: { foo: { field: "value" } } } }) ===
          JSON.stringify(body)
      );
    });
  });

  describe("#addEncryptedDataToBody", () => {
    it("encrypting first level field", () => {
      const body = {
        firstLevelField: "secret",
        anotherFirstLevelField: "value"
      };
      const expected = JSON.stringify({
        anotherFirstLevelField: "value",
        encryptedData: "changed"
      });
      const value = { encryptedData: "changed" };
      const path = { element: 'firstLevelField', obj: 'encryptedData' };
      utils.addEncryptedDataToBody(value, path, "encryptedData", body);
      assert.strictEqual(JSON.stringify(body), expected);
    });

    it("encryptedValueFieldName is not in the path", () => {
      const body = {
        field: "secret",
        anotherField: "value"
      };
      const expected = JSON.stringify({
        anotherField: "value",
        encryptedField: {
          encryptedData: "changed"
        }
      });
      const value = { encryptedData: "changed" };
      const path = { element: 'field', obj: 'encryptedField' };
      utils.addEncryptedDataToBody(value, path, "encryptedData", body);
      assert.strictEqual(JSON.stringify(body), expected);
    });

    it("encrypting to existing field", () => {
      const body = {
        field: "secret",
        anotherField: "value"
      };
      const expected = JSON.stringify({
        anotherField: "value",
        field: "changed"
      });
      const value = { field: "changed" };
      const path = { element: 'field', obj: 'field' };
      utils.addEncryptedDataToBody(value, path, "field", body);
      assert.strictEqual(JSON.stringify(body), expected);
    });

    it("encrypting to existing subfield", () => {
      const body = {
        field: {
          subField: "secret"
        },
        anotherField: "value"
      };
      const expected = JSON.stringify({
        field: {
          subField: "changed"
        },
        anotherField: "value"
      });
      const value = { subField: "changed" };
      const path = { element: 'field.subField', obj: 'field' };
      utils.addEncryptedDataToBody(value, path, "subField", body);
      assert.strictEqual(JSON.stringify(body), expected);
    });

    it("encrypting to new subfield", () => {
      const body = {
        field: {
          subField: "secret"
        },
        anotherField: "value"
      };
      const expected = JSON.stringify({
        field: {
          encryptedData: "changed"
        },
        anotherField: "value"
      });
      const value = { encryptedData: "changed" };
      const path = { element: 'field.subField', obj: 'field' };
      utils.addEncryptedDataToBody(value, path, "encryptedData", body);
      assert.strictEqual(JSON.stringify(body), expected);
    });
  });

  describe("#getPrivateKey", () => {
    it("empty p12 file", () => {
      assert.throws(() => {
        utils.getPrivateKey({ 
          keyStore: "./test/res/empty.p12",
          keyStoreAlias: "mykeyalias",
          keyStorePassword: "Password1", });
      }, /p12 keystore content is empty/);
    });
    
    it("empty p12 file unknown extension", () => {
      assert.throws(() => {
        utils.getPrivateKey({ 
          keyStore: "./test/res/keys/pkcs12/empty_key_container.unknown_extension",
          keyStoreAlias: "mykeyalias",
          keyStorePassword: "Password1", });
      }, /p12 keystore content is empty/);
    });

    it("empty alias", () => {
      assert.throws(() => {
        utils.getPrivateKey({
          keyStore: "./test/res/keys/pkcs12/test_key_container.p12",
        });
      }, /Key alias is not set/);
    });

    it("empty password", () => {
      assert.throws(() => {
        utils.getPrivateKey({
          keyStore: "./test/res/keys/pkcs12/test_key_container.p12",
          keyStoreAlias: "keyalias",
        });
      }, /Keystore password is not set/);
    });

    it("valid p12", () => {
      const pk = utils.getPrivateKey({
        keyStore: "./test/res/keys/pkcs12/test_key_container.p12",
        keyStoreAlias: "mykeyalias",
        keyStorePassword: "Password1",
      });
      assert.ok(pk);
    });

    it("valid p12, alias not found", () => {
      assert.throws(() => {
        utils.getPrivateKey({
          keyStore: "./test/res/keys/pkcs12/test_key_container.p12",
          keyStoreAlias: "mykeyalias1",
          keyStorePassword: "Password1",
        });
      }, /No key found for alias \[mykeyalias1\]/);
    });

    it("valid p12, unknown extension", () => {
      const pk = utils.getPrivateKey({
        keyStore: "./test/res/keys/pkcs12/test_key_container.unknown_extension",
        keyStoreAlias: "mykeyalias",
        keyStorePassword: "Password1",
      });
      assert.ok(pk);
    });

    it("empty unencrypted file keyStore", () => {
      assert.throws(() => {
        utils.getPrivateKey({ keyStore: "./test/res/empty.pem" });
      }, /private key file content is empty/);
    });

    it("valid pkcs8 pem in keyStore", () => {
      const pk = utils.getPrivateKey({
        keyStore: "./test/res/keys/pkcs8/test_key.pem",
      });
      assert.ok(pk);
    });

    it("valid pkcs1 pem in keyStore", () => {
      const pk = utils.getPrivateKey({
        keyStore: "./test/res/keys/pkcs1/test_key.pem",
      });
      assert.ok(pk);
    });

    it("valid pkcs8 der in keyStore", () => {
      const pk = utils.getPrivateKey({
        keyStore: "./test/res/keys/pkcs8/test_key.der",
      });
      assert.ok(pk);
    });

    it("valid pkcs1 der in keyStore", () => {
      const pk = utils.getPrivateKey({
        keyStore: "./test/res/keys/pkcs1/test_key.der",
      });
      assert.ok(pk);
    });

    it("empty unencrypted file in privateKey", () => {
      assert.throws(() => {
        utils.getPrivateKey({ privateKey: "./test/res/empty.pem" });
      }, /private key file content is empty/);
    });

    it("valid pkcs8 pem in privateKey", () => {
      const pk = utils.getPrivateKey({
        privateKey: "./test/res/keys/pkcs8/test_key.pem",
      });
      assert.ok(pk);
    });

    it("valid pkcs1 pem in privateKey", () => {
      const pk = utils.getPrivateKey({
        privateKey: "./test/res/keys/pkcs1/test_key.pem",
      });
      assert.ok(pk);
    });

    it("valid pkcs8 der in privateKey", () => {
      const pk = utils.getPrivateKey({
        privateKey: "./test/res/keys/pkcs8/test_key.der",
      });
      assert.ok(pk);
    });

    it("valid pkcs1 der in privateKey", () => {
      const pk = utils.getPrivateKey({
        privateKey: "./test/res/keys/pkcs1/test_key.der",
      });
      assert.ok(pk);
    });
  });

  describe("#readPublicCertificate", () => {
    it("not valid key", () => {
      assert.throws(() => {
        utils.readPublicCertificate("./test/res/empty.key");
      }, /Public certificate content is not valid/);
    });
  });

  describe("#ToEncodedString", () => {
    it("not valid key", () => {
      assert.throws(() => {
        utils.readPublicCertificate("./test/res/empty.key");
      }, /Public certificate content is not valid/);
    });
  });

  describe("#utils.hasConfig", () => {

    it("when valid config, not found endpoint", () => {
      const ret = utils.hasConfig(testConfig, "/endpoint");
      assert.ok(ret === null);
    });

    it("when valid config, found endpoint", () => {
      const ret = utils.hasConfig(testConfig, "/resource");
      assert.ok(ret);
    });

    it("when config is null", () => {
      const ret = utils.hasConfig(null, "/resource");
      assert.ok(ret == null);
    });

    it("when path has wildcard", () => {
      const ret = utils.hasConfig(
        testConfig,
        "https://api.example.com/mappings/0123456"
      );
      assert.ok(ret.toEncrypt[0].element === "elem2.encryptedData");
      assert.ok(ret);
    });
  });

  describe("#utils.elemFromPath", () => {
    it("valid path", () => {
      const res = utils.elemFromPath("elem1.elem2", { elem1: { elem2: "test" } });
      assert.ok(res.node === "test");
      assert.ok(
        JSON.stringify(res.parent) === JSON.stringify({ elem2: "test" })
      );
    });

    it("not valid path", () => {
      const res = utils.elemFromPath("elem1.elem2", { elem2: "test" });
      assert.ok(!res);
    });
  });

});
