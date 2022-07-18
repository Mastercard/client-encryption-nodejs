const path = require('path');

module.exports = {
  entry: './index.js',
  mode: 'development',
  output: {
    filename: 'mc_encrypt.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'mcencrypt',
    libraryTarget: 'var'

  },
  node: {
    fs: "empty"
  }
//  target: 'web'
};