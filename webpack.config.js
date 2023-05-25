const path = require('path');

module.exports = {
  target: 'node',
  entry: './index.js',
  output: {
    filename: 'client-encryption-nodejs.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'mcencrypt',
    libraryTarget: 'var'
  },
};