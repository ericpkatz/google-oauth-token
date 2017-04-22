var Sequelize = require('sequelize');
var db = new Sequelize(process.env.DATABASE_URL);
var jwt = require('jwt-simple');

var User = db.define('user', {
  email: Sequelize.STRING,
  token: Sequelize.STRING
});

if(process.env.SYNC)
  db.sync({ force: true });



var express = require('express');
var swig = require('swig');
var session = require('express-session');

var passport = require('passport');
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

var path = require('path');
swig.setDefaults({cache: false});

var app = express();

app.use(express.static(path.join(__dirname, 'node_modules')));
app.engine('html', swig.renderFile);
app.set('view engine', 'html');

app.use(session({ secret: 'foo' }));

app.use(passport.initialize());

//if running locally you can have a file with your 'secrets'
//if you are deployed- set environmental variables
var config = process.env; 
if(process.env.NODE_ENV === 'development'){
  config = require('./config.json');
}
  //strategy consists of things google needs to know, plus a callback when we successfully get a token which identifies the user
  passport.use(new GoogleStrategy({
    clientID: config.CLIENT,
    clientSecret: config.SECRET,
    callbackURL: config.URL 
  }, 
  function (token, refreshToken, profile, done) { 
    //this will be called after we get a token from google 
    //google has looked at our applications secret token and the token they have sent our user and exchanged it for a token we can use
    //now it will be our job to find or create a user with googles information
    if(!profile.emails.length)//i need an email
      return done('no emails found', null);
    User.findOne({ where: {token: token} })
      .then(function(user){
        if(user)
          return user;
        return User.create({
          email: profile.emails[0].value, 
          token: token}
        );
      })
      .then(function(user){
        done(null, user); 
      });
  }));

//root route- return user if you have one
app.get('/', function(req, res, next){
  res.render('index', { user: req.user });
});

//passport will take care of authentication
app.get('/login/google', passport.authenticate('google', {
	scope: 'email',
  session: false
}));

//here is our callback - passport will exchange token from google with a token which we can use.
app.get('/auth/google/callback', passport.authenticate('google', {
	failureRedirect: '/',
  session: false
}), function(req, res,next){
  var jwtToken = jwt.encode({ id: req.user.id }, process.env.JWT_SECRET);
  res.redirect(`/#token=${jwtToken}`);
});

app.get('/api/session/:token', (req, res, next)=> {
  var jwtToken = jwt.decode(req.params.token, process.env.JWT_SECRET);
  User.findById(jwtToken.id)
    .then( user => res.send(user))
    .catch(next);
});

app.listen(process.env.PORT || 3000);
