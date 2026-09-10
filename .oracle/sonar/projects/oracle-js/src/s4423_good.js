// S4423 good: modern TLS protocol configured on a Node HTTPS request.
const https = require('node:https');
const request = https.request({ secureProtocol: 'TLS_method' }, response => response.resume());
module.exports = { request };
