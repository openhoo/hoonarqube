app.post('/login', (req, res) => {
  req.session.user = req.body.user;
  res.redirect('/');
});
