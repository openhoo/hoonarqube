// S3330 bad: cookie written without the 'httpOnly' option.
function remember(res) {
  res.cookie("theme", "dark", { secure: true });
}
module.exports = { remember };
