const express = require("express");

const staticFiles = express.static("public", { dotfiles: "ignore" });
