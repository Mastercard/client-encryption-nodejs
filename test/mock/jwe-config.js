module.exports = {
  paths: [
    {
      path: "/resource",
      toEncrypt: [
        {
          element: "elem1.encryptedData",
          obj: "elem1",
        },
      ],
      toDecrypt: [
        {
          element: "foo.elem1",
          obj: "foo",
        },
        {
          element: "encryptedData",
          obj: "decryptedData",
        },
      ],
    },
    {
      path: "/mappings/*",
      toEncrypt: [
        {
          element: "elem2.encryptedData",
          obj: "elem2",
        },
      ],
      toDecrypt: [
        {
          element: "foo.elem1",
          obj: "foo",
        },
      ],
    },
    {
      path: "/array-resp$",
      toEncrypt: [
        {
          element: "$",
          obj: "$",
        },
      ],
      toDecrypt: [
        {
          element: "$",
          obj: "$",
        },
      ],
    },
    {
      path: "/array-resp2",
      toEncrypt: [
        {
          element: "$",
          obj: "$",
        },
      ],
      toDecrypt: [
        {
          element: "$",
          obj: "path.to.foo",
        },
      ],
    },
  ],
  mode: "JWE",
  encryptedValueFieldName: "encryptedData",
  publicKeyFingerprintType: "certificate",
  dataEncoding: "base64",
  encryptionCertificate: "./test/res/test_certificate.cert",
  privateKey: "./test/res/test_key.der",
};
