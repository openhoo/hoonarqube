const express = require('express');
const passport = require('passport');
const app = express();
app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), function (req, res) {
  res.redirect('/');
});
module.exports = { app };
