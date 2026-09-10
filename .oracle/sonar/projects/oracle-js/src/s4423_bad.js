// S4423 bad: outdated TLS protocol configured on a Node HTTPS request.
const https = require('node:https');
const request = https.request({ secureProtocol: 'TLSv1_method' }, response => response.resume());
module.exports = { request };
