(function () {
  'use strict';

  // PasswordValidator service used for testing the password strength
  angular
    .module('mean.users')
    .factory('PasswordValidator', PasswordValidator);

  // PasswordValidator.$inject = ['$window'];

  function PasswordValidator() {
    // var owaspPasswordStrengthTest = $window.owaspPasswordStrengthTest;
    var owaspPasswordStrengthTest = require('owasp-password-strength-test');

    var service = {
      getResult: getResult,
      getPopoverMsg: getPopoverMsg
    };

    return service;

    function getResult(password) {
      var result = owaspPasswordStrengthTest.test(password);
      return result;
    }

    function getPopoverMsg() {
      var popoverMsg = 'Please enter a passphrase or password with ' + owaspPasswordStrengthTest.configs.minLength + ' or more characters, numbers, lowercase, uppercase, and special characters.';

      return popoverMsg;
    }
  }

}());