# passport-direct-openidconnect
Direct OpenID Connect authentication strategy for Passport and Node.js.

# Install

    npm install passport-direct-openidconnect

# Configuration

    var passport = require('passport')
      , DirectStrategy = require('passport-direct-openidconnect').Strategy;

    passport.use(new DirectStrategy({
        clientID: DIRECT_OPENID_CLIENT_ID,
        clientSecret: DIRECT_OPENID_CLIENT_SECRET,
        callbackURL: "http://www.example.com/auth/direct/callback"
      },
      function(iss, sub, profile, accessToken, refreshToken, done) {
        User.findOrCreate(..., function(err, user) {
          if (err) { return done(err); }
          done(null, user);
        });
      }
    ));

# Routes

    app.get('/auth/direct', passport.authenticate('direct'));
    app.get('/auth/direct/callback',
      passport.authenticate('direct', { successRedirect: '/',
                                        failureRedirect: '/login' }));

# Link

    <a href="/auth/direct">Sign in with Direct</a>

