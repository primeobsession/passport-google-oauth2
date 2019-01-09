// Load modules.
var OAuth2Strategy = require('passport-oauth2')
  , util = require('util')
  , uri = require('url')
  , GooglePlusProfile = require('./profile/googleplus')
  , OpenIDProfile = require('./profile/openid')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , GooglePlusAPIError = require('./errors/googleplusapierror')
	, logger = require('winston'),
  , UserInfoError = require('./errors/userinfoerror');



/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by delegating to
 * Google using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Google application's client id
 *   - `clientSecret`  your Google application's client secret
 *   - `callbackURL`   URL to which Google will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new GoogleStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/google/callback'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/v2/auth';
  options.tokenURL = options.tokenURL || 'https://www.googleapis.com/oauth2/v4/token';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'google';
  this._userProfileURL = options.userProfileURL || 'https://www.googleapis.com/plus/v1/people/me';

  var url = uri.parse(this._userProfileURL);
  if (url.pathname.indexOf('/userinfo') == (url.pathname.length - '/userinfo'.length)) {
    this._userProfileFormat = 'openid';
  } else {
    this._userProfileFormat = 'google+'; // Google Sign-In
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Google.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `google`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(req, accessToken, done) {
  var self = this;

  // Respect URLs that already have params
  var seperator = (this._userProfileURL.indexOf('?')>-1) ? '&' : '?';

  // Express really should have trust proxy setup if this is going to be behind a proxy
  // e.g. app.enable('trust proxy');
  var userIp = req.ip;

  // Update the url with the user's IP
  this._userProfileURL = this._userProfileURL + seperator + 'userIp=' + userIp;



  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {




    var json;

    if (err) {

			logger.log('error', {
				profile: this._userProfileURL,
				userIp: userIp,
				err: err
			})

      if (err.data) {
        try {
          json = JSON.parse(err.data);
        } catch (_) {}
      }

      if (json && json.error && json.error.message) {
        return done(new GooglePlusAPIError(json.error.message, json.error.code));
      } else if (json && json.error && json.error_description) {
        return done(new UserInfoError(json.error_description, json.error));
      }
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }


    if(!err){
			logger.log('warn', {
				profile: this._userProfileURL,
				userIp: userIp,
				err: err
			})
		}

    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }

    var profile;
    switch (self._userProfileFormat) {
      case 'openid':
        profile = OpenIDProfile.parse(json);
        break;
      default: // Google Sign-In
        profile = GooglePlusProfile.parse(json);
        break;
    }

    profile.provider  = 'google';
    profile._raw = body;
    profile._json = json;

    done(null, profile);
  });
}

/**
 * Return extra Google-specific parameters to be included in the authorization
 * request.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function(options) {
  var params = {};

  // https://developers.google.com/identity/protocols/OAuth2WebServer
  if (options.accessType) {
    params['access_type'] = options.accessType;
  }
  if (options.prompt) {
    params['prompt'] = options.prompt;
  }
  if (options.loginHint) {
    params['login_hint'] = options.loginHint;
  }
  if (options.includeGrantedScopes) {
    params['include_granted_scopes'] = true;
  }

  // https://developers.google.com/identity/protocols/OpenIDConnect
  if (options.display) {
    // Specify what kind of display consent screen to display to users.
    //   https://developers.google.com/accounts/docs/OpenIDConnect#authenticationuriparameters
    params['display'] = options.display;
  }

  // Google Apps for Work
  if (options.hostedDomain || options.hd) {
    // This parameter is derived from Google's OAuth 1.0 endpoint, and (although
    // undocumented) is supported by Google's OAuth 2.0 endpoint was well.
    //   https://developers.google.com/accounts/docs/OAuth_ref
    params['hd'] = options.hostedDomain || options.hd;
  }

  // Google+
  if (options.requestVisibleActions) {
    // Space separated list of allowed app actions
    // as documented at:
    //  https://developers.google.com/+/web/app-activities/#writing_an_app_activity_using_the_google_apis_client_libraries
    //  https://developers.google.com/+/api/moment-types/
    params['request_visible_actions'] = options.requestVisibleActions;
  }

  // OpenID 2.0 migration
  if (options.openIDRealm) {
    // This parameter is needed when migrating users from Google's OpenID 2.0 to OAuth 2.0
    //   https://developers.google.com/accounts/docs/OpenID?hl=ja#adjust-uri
    params['openid.realm'] = options.openIDRealm;
  }

  // Undocumented
  if (options.approvalPrompt) {
    params['approval_prompt'] = options.approvalPrompt;
  }
  if (options.userID) {
    // Undocumented, but supported by Google's OAuth 2.0 endpoint.  Appears to
    // be equivalent to `login_hint`.
    params['user_id'] = options.userID;
  }

  return params;
}



// Overriding authenticate to pass the request into the get profile call so we can specifiy the IP address of the user
// we are making this request for.  If we don't do this the request quotas for the API do not count against the
// per user quota.
// See: https://developers.google.com/+/web/api/rest/
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = uri.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = uri.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId
  }

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }

      var code = req.query.code;

      var params = self.tokenParams(options);
      params.grant_type = 'authorization_code';
      if (callbackURL) { params.redirect_uri = callbackURL; }

      self._oauth2.getOAuthAccessToken(code, params,
        function(err, accessToken, refreshToken, params) {
          if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

          self._loadUserProfile(req, accessToken, function(err, profile) {
            if (err) { return self.error(err); }

            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }

              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    }

    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }

    var state = options.state;
    if (state) {
      params.state = state;
      var location = this._oauth2.getAuthorizeUrl(params);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }

        if (state) { params.state = state; }
        var location = self._oauth2.getAuthorizeUrl(params);
        self.redirect(location);
      }

      try {
        var arity = this._stateStore.store.length;
        if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};


/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
Strategy.prototype._loadUserProfile = function(req, accessToken, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(req, accessToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
