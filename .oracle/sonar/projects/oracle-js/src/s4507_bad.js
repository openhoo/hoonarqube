// S4507 bad: error-handling middleware mounted outside debug guards.
const express = require("express");
const errorHandler = require("errorhandler");
const app = express();
app.use(errorHandler());
module.exports = { app };
