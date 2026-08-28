const url = require("url");

const request = url.request;

request("https://example.com", { rejectUnauthorized: false });
