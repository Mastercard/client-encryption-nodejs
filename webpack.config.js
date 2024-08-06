const path = require('path');

module.exports = {
  entry: './index.js',
  output: {
    filename: 'client-encryption-nodejs.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'mcencrypt',
    libraryTarget: 'var'

  },
  {
  resolve: {
    fallback: {
      fs: false
    }
  }
},
};
