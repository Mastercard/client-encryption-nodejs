const assert = require("assert");
const MCService = require("../lib/mcapi/mcapi-service");
const testConfig = require("./mock/config");

describe("MC API Service", () => {
  describe("#interceptor", () => {
    it("when null", () => {
      assert.throws(() => {
        new MCService(null, testConfig);
      }, /service should be a valid OpenAPI client./);
    });

    it("with not right openapi client", () => {
      assert.throws(() => {
        new MCService({}, testConfig);
      }, /service should be a valid OpenAPI client./);
      assert.throws(() => {
        new MCService({ ApiClient: {} }, testConfig);
      }, /service should be a valid OpenAPI client./);
    });

    it("callApi intercepted for ApiClient with collectionQueryParams", function (done) {
      const postBody = {
        elem1: {
          encryptedData: {
            accountNumber: "5123456789012345",
          },
        },
      };
      const service = {
        ApiClient: {
          instance: {
            callApi: function () {
              arguments[arguments.length - 1](null, arguments[7], {
                body: arguments[7],
                request: { url: "/resource" },
              });
            },
          },
        },
      };
      const mcService = new MCService(service, testConfig);
      // simulate callApi call from client
      service.ApiClient.instance.callApi.call(
        mcService,
        "/resource",
        "POST",
        null,
        null,
        null,
        { test: "header" },
        null,
        postBody,
        null,
        null,
        null,
        null,
        null,
        function cb(error, data) {
          assert.ok(data.elem1.encryptedData);
          assert.ok(data.elem1.encryptedKey);
          assert.ok(data.elem1.publicKeyFingerprint);
          assert.ok(data.elem1.oaepHashingAlgorithm);
          done();
        }
      );
    });

    it("callApi intercepted for ApiClient without collectionQueryParams", function (done) {
      const postBody = {
        elem1: {
          encryptedData: {
            accountNumber: "5123456789012345",
          },
        },
      };
      const service = {
        ApiClient: {
          instance: {
            callApi: function () {
              arguments[arguments.length - 1](null, arguments[6], {
                body: arguments[6],
                request: { url: "/resource" },
              });
            },
          },
        },
      };
      const mcService = new MCService(service, testConfig);
      // simulate callApi call from client
      service.ApiClient.instance.callApi.call(
        mcService,
        "/resource",
        "POST",
        null,
        null,
        { test: "header" },
        null,
        postBody,
        null,
        null,
        null,
        null,
        null,
        function cb(error, data) {
          assert.ok(data.elem1.encryptedData);
          assert.ok(data.elem1.encryptedKey);
          assert.ok(data.elem1.publicKeyFingerprint);
          assert.ok(data.elem1.oaepHashingAlgorithm);
          done();
        }
      );
    });

    it("callApi intercepted, without body", function (done) {
      const service = {
        ApiClient: {
          instance: {
            callApi: function () {
              arguments[arguments.length - 1](null, arguments[7], {
                body: arguments[7],
                request: { url: "/resource" },
              });
            },
          },
        },
      };
      const mcService = new MCService(service, testConfig);
      // simulate callApi call from client
      service.ApiClient.instance.callApi.call(
        mcService,
        "/resource",
        "POST",
        null,
        null,
        null,
        { test: "header" },
        null,
        null,
        function cb(error, data) {
          assert.ok(!data);
          done();
        }
      );
    });
  });
});
