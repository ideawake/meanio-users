'use strict';
var mongoose = require('mongoose'),
  User = mongoose.model('User'),
  _ = require('lodash');


var findUser = exports.findUser = function(id, cb) {
  User.findOne({
    _id: id
  }, function(err, user) {
    if (err || !user) return cb(null);
    cb(user);
  });
};

const jwt = require('jsonwebtoken');
const config = require('meanio').getConfig();


/**
 * Generic require login routing middleware
 */
exports.requiresLoginCheckDb = function(req, res, next) {
  //console.log(".................................Checking auth.requiresLogin.................................");

  if (!req.isAuthenticated()) {
    return res.status(401).send('User is not authorized');
  }
  findUser(req.user._id, function(user) {
      if (!user) return res.status(401).send('User is not authorized');
      req.user = user;
      next();
  });
};

exports.requiresLogin = function requiresLogin(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).send('User is not authorized');
  }
  next();
};

/**
 * Generic require Admin routing middleware
 * Basic Role checking - future release with full permission system
 */
exports.requiresAdmin = function(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).send('User is not authorized');
  }
  findUser(req.user._id, function(user) {
      if (!user) return res.status(401).send('User is not authorized');

      if (req.user.roles.indexOf('admin') === -1) return res.status(401).send('User is not authorized');
      req.user = user;
      next();
  });
};

/**
 * Generic validates if the first parameter is a mongo ObjectId
 */
exports.isMongoId = function(req, res, next) {
  if ((_.size(req.params) === 1) && (!mongoose.Types.ObjectId.isValid(_.values(req.params)[0]))) {
      return res.status(500).send('Parameter passed is not a valid Mongo ObjectId');
  }
  next();
};


exports.generateAuthToken = function(MeanUser) {
  return (req, res, next) => {
    try {
      let payload = req.user;
      let escaped, token;

      if (MeanUser) {
        MeanUser.events.publish({
          action: 'logged_in',
          user: {
            name: req.user.name
          }
        });
      }

      (req.body.hasOwnProperty('redirect') && req.body.redirect !== false) &&
      (payload.redirect = req.body.redirect);

      escaped = JSON.stringify(payload);
      escaped = encodeURI(escaped);

      req.token = jwt.sign(escaped, config.secret);

      next();
    } catch (err) {
      next(err);
    }
  }
};


exports.SAMLAuthorization = function(req, res, next) {
  User.findOneUser({email: req.user.upn}, true)
  .then(user => {
    if (!user) {
      // TODO: user creation should be refactored to use one common method for creating user
      // Current sign up logic is ther in the controller which needs to be moved out
      // to a re-usable method on the model
      let newUser = new User({
        email: req.user.upn,
        name: req.user.name,
        adfs_metadata: req.user
      });
      return newUser.save()
      .catch(err => {
        console.log('Error creating user on SSO', err);
        res.json({err});
        return Promise.reject(err);
        // TODO: this error needs to be handled using a proper error response page
      });
    } else {
      return user;
    }
  })
  .then(user => {
    req.user = user;
    next();
  });
};
