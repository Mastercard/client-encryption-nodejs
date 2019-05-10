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
      let res = utils.bytesToString({}, 'hex');
      assert.ok(res === "");
    });

    it("when empty str", () => {
      let res = utils.bytesToString("", 'hex');
      assert.ok(res === "");
    });

    it("when wrong encoding", () => {
      let res = utils.bytesToString("abc", 'XXX');
      assert.ok(res === "YWJj"); // default is base64
    });

    it("when test str hex", () => {
      let res = utils.bytesToString("test", 'hex');
      assert.ok(res === "74657374");
    });

    it("when test str base64", () => {
      let res = utils.bytesToString("test", 'base64');
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
      let res = utils.stringToBytes({}, 'hex');
      assert.ok(res === "");
    });

    it("when empty str", () => {
      let res = utils.stringToBytes("", 'hex');
      assert.ok(res === "");
    });

    it("when wrong encoding", () => {
      let res = utils.stringToBytes("dGVzdGluZ3V0aWxz", 'XXX');
      assert.ok(res === "testingutils");
    });

    it("when test str hex", () => {
      let res = utils.stringToBytes("74657374696E677574696C73", 'hex');
      assert.ok(res === "testingutils");
    });

    it("when test str base64", () => {
      let res = utils.stringToBytes("dGVzdGluZ3V0aWxz", 'base64');
      assert.ok(res === "testingutils");
    });

    it("encoding and decoding base64", () => {
      let str = "dGVzdGluZ3V0aWxz";
      let res = utils.stringToBytes(str, "base64");
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
      let res = utils.jsonToString({});
      assert.ok(res === "{}");
    });

    it("when empty str", () => {
      assert.throws(() =>
        utils.jsonToString("")
      );
    });

    it("correct json from object", () => {
      let res = utils.jsonToString({field: "value"});
      assert.strictEqual(res, '{"field":"value"}');
    });

    it("correct json from string", () => {
      let res = utils.jsonToString('{"field": "value"}');
      assert.strictEqual(res, '{"field":"value"}');
    });

  });

  describe("#mutateObjectProperty", () => {
    it("change object value", () => {
      let obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
      };
      let path = "first.second.third";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(obj.first.second.third === "changed");
    });

    it("change object value, delete it", () => {
      let obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
      };
      let path = "first.second.third";
      utils.mutateObjectProperty(path, "changed", obj, "third");
      assert.ok(!obj.first.second.third);
    });

    it("field not found, create it", () => {
      let obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
      };
      let objStr = JSON.stringify({"first": {"second": {"third": {"field": "value"}, "not_exists": "changed"}}});
      let path = "first.second.not_exists";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

    it("field not found, create it, long path", () => {
      let obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
      };
      let objStr = JSON.stringify({
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
      let path = "foo.bar.yet.another.foo.bar";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

    it("first part of path is correct, but field not found, create it", () => {
      let obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
      };
      let objStr = JSON.stringify({
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
      let path = "first.foo.third";
      utils.mutateObjectProperty(path, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

    it("path is null", () => {
      let obj = {
        first: {
          second: {
            third: {
              field: "value"
            }
          }
        }
      };
      let objStr = JSON.stringify(obj);
      utils.mutateObjectProperty(null, "changed", obj);
      assert.ok(objStr === JSON.stringify(obj));
    });

  });

  describe("#resolveNode", () => {

    it("when null", () => {
      assert.ok(null === utils.resolveNode(null, null, false));
    });

    it("when path length == 0", () => {
      assert.ok(null === utils.resolveNode("", {}, false));
    });

    it("when not dotted", () => {
      assert.ok(null === utils.resolveNode("testpath", {}, false));
    });

    it("with valid path and obj", () => {
      let res = utils.resolveNode("test.path.long", {
        test: {
          path: {
            long: {
              foo: "bar"
            }
          }
        }
      }, false);
      assert.ok(JSON.stringify(res) === JSON.stringify({foo: "bar"}));
    });

    it("with valid path and obj not found", () => {
      let res = utils.resolveNode("test.path.notfound", {
        test: {
          path: {
            long: {
              foo: "bar"
            }
          }
        }
      }, false);
      assert.ok(res === null);
    });

    it("with valid path and obj not found, create it", () => {
      let body = {
        test: {
          path: {
            long: {
              foo: "bar"
            }
          }
        }
      };
      utils.resolveNode("test.path.notfound", body, true);
      assert.ok(JSON.stringify(body) === JSON.stringify({"test": {"path": {"long": {"foo": "bar"}, "notfound": {}}}}));
    });

  });


});
