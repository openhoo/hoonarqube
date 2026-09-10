import express from 'express';
import passport from 'passport';
const app = express();
app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login' }),
  function (req: unknown, res: unknown) {
    res.redirect('/');
  });
