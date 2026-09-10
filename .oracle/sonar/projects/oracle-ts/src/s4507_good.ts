// S4507 good: middleware unrelated to error handling mounted.
const express = require("express");
const app = express();
app.use(express.json());
module.exports = { app };
