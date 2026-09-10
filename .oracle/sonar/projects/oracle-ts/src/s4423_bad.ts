// S4423 bad: outdated TLS minimum configured on a Node HTTPS request.
import * as https from 'node:https';
const request = https.request({ hostname: 'api.example.net', minVersion: 'TLSv1' }, (response) => {
  response.resume();
});
request.end();
