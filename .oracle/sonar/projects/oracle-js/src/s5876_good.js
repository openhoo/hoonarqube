const express = require('express');
const passport = require('passport');
const app = express();
app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), function (req, res) {
  const prevSession = req.session;
  req.session.regenerate((err) => {
    Object.assign(req.session, prevSession);
    res.redirect('/');
  });
});
module.exports = { app };
