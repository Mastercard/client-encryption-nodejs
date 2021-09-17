const assert = require('assert');
const utils = require("../lib/mcapi/utils/utils");


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
        utils.bytesToString(null, 'hex');
      });
    });

    it("when undefined", () => {
      assert.throws(() => {
        utils.bytesToString(undefined, 'hex');
      });
    });

    it("when empty obj", () => {
      const res = utils.bytesToString({}, 'hex');
      assert.ok(res === "");
    });

    it("when empty str", () => {
      const res = utils.bytesToString("", 'hex');
      assert.ok(res === "");
    });

    it("when wrong encoding", () => {
      const res = utils.bytesToString("abc", 'XXX');
      assert.ok(res === "YWJj"); // default is base64
    });

    it("when test str hex", () => {
      const res = utils.bytesToString("test", 'hex');
      assert.ok(res === "74657374");
    });

    it("when test str base64", () => {
      const res = utils.bytesToString("test", 'base64');
      assert.ok(res === "dGVzdA==");
    });

  });

  describe("#stringToBytes", () => {

    it("when null", () => {
      assert.throws(() => {
        utils.stringToBytes(null, 'hex');
      });
    });

    it("when undefined", () => {
      assert.throws(() => {
        utils.stringToBytes(undefined, 'hex');
      });
    });

    it("when empty obj", () => {
      const res = utils.stringToBytes({}, 'hex');
      assert.ok(res === "");
    });

    it("when empty str", () => {
      const res = utils.stringToBytes("", 'hex');
      assert.ok(res === "");
    });

    it("when wrong encoding", () => {
      const res = utils.stringToBytes("dGVzdGluZ3V0aWxz", 'XXX');
      assert.ok(res === "testingutils");
    });

    it("when test str hex", () => {
      const res = utils.stringToBytes("74657374696E677574696C73", 'hex');
      assert.ok(res === "testingutils");
    });

    it("when test str base64", () => {
      const res = utils.stringToBytes("dGVzdGluZ3V0aWxz", 'base64');
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
      assert.throws(() =>
        utils.jsonToString("")
      );
    });

    it("correct json from object", () => {
      const res = utils.jsonToString({field: "value"});
      assert.strictEqual(res, '{"field":"value"}');
    });

    it("correct json from string", () => {
      const res = utils.jsonToString('{"field": "value"}');
      assert.strictEqual(res, '{"field":"value"}');
    });

  });

  describe("#mutateObjectProperty", () => {
    it("change object value", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
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
              field: "value"
            }
          }
        }
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
              field: "value"
            }
          }
        }
      };
      const objStr = JSON.stringify({"first": {"second": {"third": {"field": "value"}, "not_exists": "changed"}}});
      const path = "first.second.not_exists";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

    it("field not found, create it, long path", () => {
      const obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
      };
      const objStr = JSON.stringify({
        "first": {
          "second": {
            "third": {
              "field": "value"
            }
          }
        },
        "foo": {
          "bar": {
            "yet": {
              "another": {
                "foo": {
                  "bar": "changed"
                }
              }
            }
          }
        }
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
              field: "value"
            }
          }
        }
      };
      const objStr = JSON.stringify({
        "first": {
          "second": {
            "third": {
              "field": "value"
            }
          },
          "foo": {
            "third": "changed"
          }
        }
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
              field: "value"
            }
          }
        }
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
      const body = {path: {to: {foo: {field: "value"}}}};
      const str = JSON.stringify(body);
      utils.deleteNode("path.to.notfound", body, null);
      assert.ok(str === JSON.stringify(body));
    });

    it("path found, should remove it", () => {
      const body = {path: {to: {foo: {field: "value"}}}};
      utils.deleteNode("path.to.foo", body, null);
      assert.ok(JSON.stringify({path: {to: {}}}) === JSON.stringify(body));
    });

    it("root path, without properties, shouldn't remove", () => {
      const body = {path: {to: {foo: {field: "value"}}}};
      const str = JSON.stringify(body);
      utils.deleteNode("", body, null);
      assert.ok(str === JSON.stringify(body));
    });

    it("root path, with properties, should remove the properties", () => {
      const body = {path: {to: {foo: {field: "value"}}}, prop: "prop", prop2: "prop2"};
      utils.deleteNode("", body, ["prop", "prop2"]);
      assert.ok(JSON.stringify({"path": {"to": {"foo": {"field": "value"}}}}) === JSON.stringify(body));
    });

  });


});
