// S2598 bad: upload middleware without a limits object.
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
module.exports = { upload };
