
// reference: https://scotch.io/tutorials/easy-node-authentication-setup-and-local#handling-signup/registration
const passport = require('passport')
    , LocalStrategy = require('passport-local').Strategy;

// expose this function to our app using module.exports
module.exports = function() {
    // required for persistent login sessions
    // used to serialize the user for the session
    passport.use('passport-local-plugin', new LocalStrategy({
          usernameField : 'username',
          passwordField : 'password'
      }, function(username, password, done) {
        console.log(`--> incoming request of "${username}"`);
        if (username && password !== 'reject') {
          console.log(`Authentification of "${username}" ${password ? 'with' : 'without'} password`, );
          return done(null, {username: username});
        } else {
          console.log(`Authentification failed, username-field is empty`);
          return done(null, false);
        }
      }));
};
