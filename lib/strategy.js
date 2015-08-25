/**
 * Module dependencies.
 */
var OpenIDConnect = require('passport-openidconnect').Strategy,
    util = require('util');

/**
 * `Strategy` constructor.
 *
 * The Direct OpenID Connect authentication strategy authenticates requests using
 * OpenID Connect, which is an identity layer on top of the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  // https://direct4b.com/.well-known/openid-configuration
  options.authorizationURL = options.authorizationURL || 'https://direct4b.com/oauth2/authorize';
  options.tokenURL         = options.tokenURL         || 'https://direct4b.com/oauth2/token';
  options.userInfoURL      = options.userInfoURL      || 'https://api.direct4b.com/albero-app-server/users/me';

  // profile converter
  var conv = function(profile) {
    var json = profile._json;
    profile.id = json.user_id_str;
    profile.displayName = json.display_name;
    profile.emails = [json.email];
    profile.picture = json.profile_image_url;
    profile.provider = 'direct';
    return profile;
  };

  // verify replacement
  // https://github.com/jaredhanson/passport-openidconnect/blob/master/lib/strategy.js#L201
  var _verify = verify;
  if (options.passReqToCallback) {
    switch (verify.length) {
      case 9: _verify = function (req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified) {
                verify(req, iss, sub, conv(profile), jwtClaims, accessToken, refreshToken, params, verified);
              }; break;
      case 8: _verify = function (req, iss, sub, profile, accessToken, refreshToken, params, verified) {
                verify(req, iss, sub, conv(profile), accessToken, refreshToken, params, verified);
              }; break;
      case 7: _verify = function (req, iss, sub, profile, accessToken, refreshToken, verified) {
                verify(req, iss, sub, conv(profile), accessToken, refreshToken, verified);
              }; break;
      case 5: _verify = function (req, iss, sub, profile, verified) {
                verify(req, iss, sub, conv(profile), verified);
              }; break;
    }
  } else {
    switch (verify.length) {
      case 8: _verify = function (iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified) {
                verify(iss, sub, conv(profile), jwtClaims, accessToken, refreshToken, params, verified);
              }; break;
      case 7: _verify = function (iss, sub, profile, accessToken, refreshToken, params, verified) {
                verify(iss, sub, conv(profile), accessToken, refreshToken, params, verified);
              }; break;
      case 6: _verify = function (iss, sub, profile, accessToken, refreshToken, verified) {
                verify(iss, sub, conv(profile), accessToken, refreshToken, verified);
              }; break;
      case 4: _verify = function (iss, sub, profile, verified) {
                verify(iss, sub, conv(profile), verified);
              }; break;
    }
  }

  OpenIDConnect.call(this, options, _verify);
  this.name = 'direct';
}

/**
 * Inherit from `OpenIDConnect Strategy`.
 */
util.inherits(Strategy, OpenIDConnect);

/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  OpenIDConnect.prototype.authenticate.call(this, req, options);
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;

