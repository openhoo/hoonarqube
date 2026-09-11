const https = require("https");
const request = https.request;
request({ hostname: "example.com", rejectUnauthorized: true });
