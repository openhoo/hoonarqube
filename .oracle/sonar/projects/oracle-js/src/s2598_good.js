// S2598 good: disk storage with an explicit destination.
const multer = require("multer");
const upload = multer({
  storage: multer.diskStorage({ destination: "uploads/" }),
});
module.exports = { upload };
