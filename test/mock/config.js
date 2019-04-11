module.exports = {
  paths: [
    {
      path: "/resource",
      toEncrypt: [
        {
          element: "elem1.encryptedData",
          obj: "elem1"
        }],
      toDecrypt: [
        {
          element: "elem1.encryptedData",
          obj: "elem1"
        }
      ]
    },
    {
      path: "/mappings/*",
      toEncrypt: [
        {
          element: "elem2.encryptedData",
          obj: "elem2"
        }],
      toDecrypt: [
        {
          element: "elem2.encryptedData",
          obj: "elem2"
        }
      ]
    }
  ],
  oaepPaddingDigestAlgorithm: 'SHA-512',
  ivFieldName: 'iv',
  encryptedKeyFieldName: 'encryptedKey',
  encryptedValueFieldName: 'encryptedData',
  oaepHashingAlgorithmFieldName: 'oaepHashingAlgorithm',
  publicKeyFingerprintFieldName: 'publicKeyFingerprint',
  publicKeyFingerprintType: 'certificate',
  dataEncoding: 'hex',
  encryptionCertificate: "./test/res/test_certificate.cert",
  privateKey: "./test/res/test_key.der"

};
