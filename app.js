//TODO: Upload on github
require('dotenv').config(); // loads the .env file into process.env
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GithubStrategy = require('passport-github2').Strategy;
const findOrCreate = require("mongoose-findorcreate"); //to use findOrCreate function in mongoose

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
  }))
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); //to use findOrCreate function in mongoose

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); 

passport.serializeUser(function(user, done){
    done(null, user.id); // creates a cookie that saves the user's session
})

passport.deserializeUser(function(id, done){
    User.findById(id).then(function(user, err){
        done(err, user);
    });
});

//google authentication strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", // this is the url that google will redirect to after the user logs in (it must be the same as the one in the google console)
    //userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" // this is needed because of a bug
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
  }
));

//github authentication strategy
passport.use(new GithubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home");
});

app.get('/auth/google', //this allows us to click the sign up or sign in with google button
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', // this is the url that google will redirect to after the user logs in (it must be the same as the one in the google console)
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
}); 

app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'profile' ] }) //user:email
);

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.get("/secrets", function(req, res) {
    if(req.isAuthenticated()){ // checks if the user is authenticated (logged in) using cookies
        User.find({"secret": {$ne: null}}).then(
            function(foundUsers){
                if(foundUsers){
                    res.render("secrets", {usersWithSecrets: foundUsers});
                }
            }
        )// find all the users that have a secret that is not null
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()){ // checks if the user is authenticated (logged in) using cookies
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    req.logOut(function(err){
        if(err){
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});

app.post("/register", function(req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            //in the line below, function currying is used
            passport.authenticate("local")(req, res, function(){ // authenticate the user using passport (creates a cookie that saves the user's session)
                res.redirect("/secrets");
            })
        }
    });
});

app.post("/login", function(req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function(err){
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local", {failureRedirect: '/login'})(req, res, function(){  // authenticate the user using passport (creates a cookie that saves the user's session)
                res.redirect("/secrets");
            });
        }
    })
})

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    //console.log(req.user.id); // we can access the user's id using req.user.id
    //we want to save the secret to the user's document in the database (we can access the user's document using req.user)
    User.findById(req.user.id).then(function(foundUser){
        if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save().then(function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(3000, function() {
    console.log("Server started on port 3000");
});