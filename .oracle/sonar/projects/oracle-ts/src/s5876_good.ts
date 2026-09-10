import express from 'express';
import passport from 'passport';
const app = express();
app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login' }),
  function (req: unknown, res: unknown) {
    const previousSession = req.session;
    req.session.regenerate((err: Error | null) => {
      if (err) {
        res.status(500).end();
        return;
      }
      Object.assign(req.session, previousSession);
      res.redirect('/');
    });
  }
);
