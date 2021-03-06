'use strict';

/**
 * Module dependencies.
 */
var mongoose  = require('mongoose'),
  Schema    = mongoose.Schema,
  crypto    = require('crypto'),
  _   = require('lodash');

const Promise = require('bluebird');

/**
 * Validations
 */
var validatePresenceOf = function(value) {
  // If you are authenticating by any of the oauth strategies, don't validate.
  return (this.provider && this.provider !== 'local') || (value && value.length);
};

/**
 * Generates Mongoose uniqueness validator
 *
 * @param string modelName
 * @param string field
 * @param boolean caseSensitive
 *
 * @return function
 **/
function unique(modelName, field, caseSensitive) {
  return function(value, respond) {
    if(value && value.length) {
      var query = mongoose.model(modelName).where(field, new RegExp('^'+value+'$', caseSensitive ? 'i' : undefined));
      if(!this.isNew)
        query = query.where('_id').ne(this._id);
      query.count(function(err, n) {
        respond(n<1);
      });
    }
    else
      respond(false);
  };
}


// var validateUniqueEmail = function(value, callback) {
//   var User = mongoose.model('User');
//   User.find({
//     $and: [{
//       email: toLower(value)
//     }, {
//       _id: {
//         $ne: this._id
//       }
//     }]
//   }, function(err, user) {
//     callback(err || user.length === 0);
//   });
// };

// function toLower (v) {
//   return v.toLowerCase();
// }

function toLower (v) {
  if(typeof v !== 'undefined') {
    return v.toLowerCase();
  } else {
    return '';
  }
}

/**
 * Getter
 */
var escapeProperty = function(value) {
  return _.escape(value);
};

var schemaOptions = { timestamps: true };
/**
 * User Schema
 */

var UserSchema = new Schema({
  name: {
    type: String,
    required: true,
    get: escapeProperty
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    set: toLower,
    get: toLower,
    // Regexp to validate emails with more strict rules as added in tests/users.js which also conforms mostly with RFC2822 guide lines
    match: [/^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, 'Please enter a valid email'],
    validate: [unique('User', 'email'), 'E-mail address is already in-use']
  },
  secondaryEmail: {
    type: String,    
    unique: true,
    sparse: true,
    trim: true,
    set: toLower,
    get: toLower,
    // Regexp to validate emails with more strict rules as added in tests/users.js which also conforms mostly with RFC2822 guide lines
    match: [/^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, 'Please enter a valid email'],
    validate: [unique('User', 'secondaryEmail'), 'secondary E-mail address is already in-use']
  },
  username: {
    type: String,
    unique: true,
    required: false,
    get: escapeProperty
  },
  roles: {
    type: Array,
    default: ['authenticated', 'anonymous']
  },
  hashed_password: {
    type: String,
    validate: [validatePresenceOf, 'Password cannot be blank'],
    select: false
  },
  provider: {
    type: String,
    default: 'local'
  },
  tours: {
    challengeView: {
      type: Boolean,
      default: true // false means tour was seen
    },
    challengeList: {
      type: Boolean,
      default: true
    }
  },
  salt: {
    type: String,
    select: false
  },
  resetPasswordToken: {
    type: String,
    select: false
  },
  resetPasswordExpires: {
    type: Date,
    select: false
  },
  profile: {},
  facebook: {},
  twitter: {},
  github: {},
  google: {},
  linkedin: {},
  userProfile : {
    type: Schema.ObjectId,
    ref: 'UserProfile'
  },
  deleted: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  adfs_metadata: {}
}, schemaOptions);


/**
 * Virtuals
 */
UserSchema.virtual('password').set(function(password) {
  this._password = password;
  this.salt = this.makeSalt();
  this.hashed_password = this.hashPassword(password);
}).get(function() {
  return this._password;
});

/**
 * Pre-save hook
 */
UserSchema.pre('save', function(next) {
  var self = this;
  if (this.isNew && this.provider === 'local' && this.password && !this.password.length) {
    return next(new Error('Invalid password'));
  }
  
  // if it is new record send welcome email
  if (this.isNew) {
    // generate username from email
    if (!self.username) {
      let username = this.email.split('@')[0];
      mongoose.model('User').count({username}).exec()
        .then(count => {
          if (count) username = `${username}_${count}`;
          self.username = username;

          next();
        })
        .catch(err => next(err));
    }
  } else {
    next();
  }
});


UserSchema.methods = require('./instance-methods');
UserSchema.statics = require('./static-methods').user;

mongoose.model('User', UserSchema);
