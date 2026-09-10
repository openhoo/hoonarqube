// S2598 bad: disk storage without an explicit destination.
const multer = require("multer");
const upload = multer({ storage: multer.diskStorage({}) });
module.exports = { upload };
