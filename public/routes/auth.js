'use strict';

//Setting up route
angular.module('mean.users').config(['$httpProvider', 'jwtInterceptorProvider',
  function ($httpProvider, jwtInterceptorProvider) {

    function localStorageTest() {
      var test = 'test';
      try {
        localStorage.setItem(test, test);
        localStorage.removeItem(test);
        return true;
      } catch (e) {
        return false;
      }
    }

    function clearTokensAndRedirectToLogin() {
      localStorage.removeItem('JWT');
      localStorage.removeItem('rft');
      $location.url('/auth/login');
    }

    jwtInterceptorProvider.tokenGetter = ['$cookies', '$location', '$http', 'jwtHelper', function ($cookies, $location, $http, jwtHelper) {
      if (localStorageTest()) {
        var lcJwt = localStorage.getItem('JWT');
        var rft = localStorage.getItem('rft');
        var user;
        try {
          user = lcJwt ? jwtHelper.decodeToken(lcJwt) : null;
        } catch (err) {
          console.log('bad token, logging user out', lcJwt, rft);
          console.error(err);
          clearTokensAndRedirectToLogin();
          return;
        }
        if(user && typeof user.userProfile !== 'string'){
          clearTokensAndRedirectToLogin();
          return;
        } else if(lcJwt && rft && jwtHelper.isTokenExpired(lcJwt)){
          return $http({
            url: '/api/refreshtoken',
            skipAuthorization: true,
            method: 'POST',
            data: { refreshToken: rft, id: user._id }
          })
          .then(function(response) {
              if(response && response.data) {
                localStorage.setItem('JWT', response.data.token);
                return response.data.token;
              }
            })
            .catch(function(err) {
              console.log(err);
              clearTokensAndRedirectToLogin();
              return;
            });

        } else {
          return lcJwt;
        }
      } else {
        $cookies.put('nolocalstorage', 'true');
        $location.url('/unsupported-browser');
        // return $cookies.get('id_token');
      }
    }];

    $httpProvider.interceptors.push('jwtInterceptor');
  }
]);
