const jwt = require("jsonwebtoken");

const token = jwt.sign({ sub: "user" }, "key", { algorithm: "none" });
