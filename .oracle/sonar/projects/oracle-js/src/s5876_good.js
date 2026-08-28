app.post('/login', (req, res) => {
  req.session.regenerate(() => {});
  req.session.user = req.body.user;
  res.redirect('/');
});
