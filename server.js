// if we're not in production (in development), require the development dependency 
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

const express = require('express');
const app = express();
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

// require the passport function
const initializePassport = require('./passport-config');
initializePassport(
    passport, // passport we're configuring
    email => users.find(user => user.email === email),  // function for finding the user based on the email
    id => users.find(user => user.id === id)
);

// password hash
const bcrypt = require('bcrypt');
app.listen(5000); // port

// temporary user array (db will be used in production)
const users = [];

// tell server we're using ejs syntax
app.set('view-engine', 'ejs'); 

// tell server we want to be able to use inside request variable (e.g. req.body.variable)
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({ 
    secret: process.env.SESSION_SECRET,
    resave: false,  // we don't want to save session if nothing is changed
    saveUninitialized: false  // we don't want to save empty value to session
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name});
});

// login get and post
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

// uses authenticate middleware
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',       // login successful, direct to home page
    failureRedirect: '/login',  // login failure, redirect to login
    failureFlash: true          // login failure, display message
}));

// register get and post
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10); // 10 times = general number of hashes to make it secure
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });
        res.redirect('/login');
    } catch {
        res.redirect('/register');
    }
});

app.delete('/logout', (req, res) => {
    req.logOut();   // log out function set up by passport, clears session and logs user out
    res.redirect('/login');
})

// check if user authenticated (logged in)
function checkAuthenticated (req, res, next) {
    if (req.isAuthenticated()){  // function that returns true if user is authenticated
        return next();
    }
    res.redirect('/login');
}

// check if user not authenticated (not logged in)
function checkNotAuthenticated (req, res, next) {
    if (req.isAuthenticated()){ 
        return res.redirect('/');
    }
    next()
}
