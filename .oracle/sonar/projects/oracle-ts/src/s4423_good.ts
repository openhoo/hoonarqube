// S4423 good: modern TLS minimum configured on a Node HTTPS request.
import * as https from 'node:https';
const request = https.request({ hostname: 'api.example.net', minVersion: 'TLSv1.2' }, (response) => {
  response.resume();
});
request.end();
