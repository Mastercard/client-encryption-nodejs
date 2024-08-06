const path = require('path');

module.exports = {
  entry: './index.js',
  output: {
    filename: 'client-encryption-nodejs.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'mcencrypt',
    libraryTarget: 'var'
  },
  node: {
    global: false,
    __filename: false,
    __dirname: false,
  },
  resolve: {
  modules: [...],
  fallback: {
    "fs": false,
    "tls": false,
    "net": false,
    "path": false,
    "zlib": false,
    "http": false,
    "https": false,
    "stream": false,
    "crypto": false,
    "crypto-browserify": require.resolve('crypto-browserify'), //if you want to use this module also don't forget npm i crypto-browserify 
  } 
},
};
