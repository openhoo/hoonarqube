// S4830 good: environment assignment unrelated to TLS validation.
process.env.NODE_ENV = "production";
module.exports = { env: process.env.NODE_ENV };
