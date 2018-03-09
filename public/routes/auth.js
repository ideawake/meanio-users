'use strict';

//Setting up route
angular.module('mean.users').config(['$httpProvider', 'jwtInterceptorProvider',
  function($httpProvider, jwtInterceptorProvider) {    

  	function localStorageTest() {
	    var test = 'test';
	    try {
        localStorage.setItem(test, test);
        localStorage.removeItem(test);
        return true;
	    } catch(e) {
        return false;
	    }
		}

    jwtInterceptorProvider.tokenGetter = ['$cookies', '$location', '$http', 'jwtHelper', function($cookies, $location, $http, jwtHelper) {
      if (localStorageTest()) {
        var lcJwt = localStorage.getItem('JWT');
        var rft = localStorage.getItem('rft');
        var user = lcJwt ? jwtHelper.decodeToken(lcJwt) : null;
        if(user &&  typeof user.userProfile !== 'string'){
          localStorage.removeItem('JWT');
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
              localStorage.removeItem('JWT');
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
