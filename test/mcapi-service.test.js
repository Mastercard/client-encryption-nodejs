const assert = require("assert");
const MCService = require("../lib/mcapi/mcapi-service");
const testConfig = require("./mock/config");
const testJweConfig = require("./mock/jwe-config")

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

/* This test case showcases the encryption and decryption of the entire payload using JWE. It describes a scenario where encryption generates encryptedData object. Upon making an API call, the API responds with an encryptedResponse object. The test verifies the ability to decrypt the encryptedResponse object. */
it("Intercepting ApiClient's callApi with JWE Encryption/Decryption for Entire Payload, Utilizing Different Request and Response Objects",
  function (done) {
    const postBody = {
      externalReference: "48956hguyguy23g4234",
      amount: "2",
      payers: [{ accountAlias: "stg_earmark_payer1withcryptoaddr-999000", amount: "2" }],
      recipients: [{ accountAlias: "stg_earmark_recip1WithCryptoAddr-999001", amount: "1" }]
    };
    const respEnc =
    {
      encryptedResponse: 'eyJraWQiOiJnSUVQd1RxREdmenc0dXd5TElLa3d3UzNnc3c4NW5FWFkwUFA2QllNSW5rPSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24iLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.' +
        'flEVAmFsw70aH6cyCmU8PmJSGBjWM8QU8rQg2IvfHZjvBq0O7qtRjIn9ssmTlYAohXxO4uIuECUWv9NILdZnKd20wtgihBmrflKVhVZ8afJESFIEcF4vIY03QBou0u4bGVNtrC0XooPy6uRnkZzlcvDZyMVMJF4eEK1-PSx7Gf77Vj9q37S' +
        'IHsVCo4EujDi6Y1qRz2kI86eIguLeJbFmL1VcOUyrt8jtjcj00utFm30j-PyOEwgiyhYI6F0eMUWT89d-QYQrInk-Ciyp4bYwsLcr85BOMqWZ8nc2CGu2rfBNGexCphxDUJQ/TWEBZ0XKBAaQOj5qszwXhO-synLJ3A.eIGqscNMcz5h8x8w26oc6A.' +
        'y-66zjYqTEqmgV39rklNVKgCF1Uq6jf-sLKOOkkX6RZJsAl4UY4cHWEfWcJCgnMnS8ZE/sBen24FwjZrxlC/znJa4D-BoY4OK0oE/GQJZ9mkmzwbqKeBFLzmalVLG2/XH74TY6bVn5xtVSR9tCalEMjIEo/Wwyt1DbIdysFqfcmXUbJo4bmKx6rfpBbXn' +
        'cOopJ8nxQZaXueM1BcZQykS8bl4GriF2NgtPdjz6aqXsxDihd3p7LpbobrdcFtZvsMTs6xTRia9q9qqzN70cKwM8lBftMdRovRa-JCrkJ7LDqDQ/A.cdFqkuHXnggBcfxugl8cBA'
    };
    const service = {
      ApiClient: {
        instance: {
          callApi: function () {
            arguments[arguments.length - 1](null, arguments[7],
              {
                body: arguments[7],
                request: { url: "/entirepayload" },
                returnApiResponse: respEnc,
              });
          },
        },
      },
    };
    const mcService = new MCService(service, testJweConfig);
    // simulate callApi call from client 
    service.ApiClient.instance.callApi.call(mcService,
      "/entirepayload",
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
        assert.ok(data.externalReference);
        assert.ok(data.amount);
        assert.ok(data.payers);
        assert.ok(data.recipients);
        done();
      });
  });
