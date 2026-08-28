// S3330 good: 'httpOnly' enabled alongside 'secure'.
function remember(res) {
  res.cookie("theme", "dark", { secure: true, httpOnly: true });
}
module.exports = { remember };
