// S2598 good: upload middleware with explicit limits.
const multer = require("multer");
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 1048576, files: 5 },
});
module.exports = { upload };
