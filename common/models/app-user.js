'use strict';
const csv = require('csvtojson');
const JWT = require("jsonwebtoken");
const path = require('path');
const fs = require('fs');
const RestError = require('../../server/utils/rest-error.js');
const { JWT_SECRET } = require("../../server/configuration");
const bcrypt = require("bcryptjs");
const jwtDecode = require("jwt-decode");

module.exports = function (AppUser) {


  function signToken(user) {
    return JWT.sign(
      {
        iss: "Vikas",
        sub: user.id,
        iat: new Date().getTime(),
        exp: new Date().setDate(new Date().getDate() + 1),
      },
      JWT_SECRET
    );
  };


  AppUser.signUp = function (email, password, username, req, callback) {

    const promise = new Promise((resolve, reject) => {

      AppUser.findOne({
        where: {
          email: email
        }
      })
        .then((user) => {

          if (user) {
            return reject(new RestError(400, `Email already exists!`));
          }

          let ipAddress = 'no-ip';
          if (req && req.headers['x-forwarded-for']) {
            ipAddress = req.headers['x-forwarded-for'];
          }

          let newUser = {
            email: email,
            password: encryptPassword(password),
            username: username,
            ipAddress: ipAddress
          };

          return AppUser.create(newUser);

        })
        .then((userDetails) => {
          let token = signToken(userDetails);

          return resolve(token);
        })
        .then((userDetails) => {
          return resolve(userDetails);
        }).catch(reject);
    });

    if (callback !== null && typeof callback === 'function') {
      promise.then(function (data) { return callback(null, data); }).catch(function (err) { return callback(err); });
    } else {
      return promise;
    }
  }

  AppUser.remoteMethod('signUp', {
    accepts: [
      {
        arg: 'email',
        type: 'string',
        http: {
          source: 'form'
        }
      },
      {
        arg: 'email',
        type: 'string',
        http: {
          source: 'form'
        }
      },
      {
        arg: 'username',
        type: 'string',
        http: {
          source: 'form'
        }
      },
      {
        arg: 'req',
        type: 'object',
        http: {
          source: 'req'
        }
      }
    ],
    returns: {
      arg: 'data',
      type: 'object',
      root: true
    },
    http: {
      path: '/signUp',
      verb: 'POST'
    },
    description: 'user signUp'
  });


  AppUser.login = function (username, password, req, callback) {


    const promise = new Promise((resolve, reject) => {

      const token = verifyToken(req);

      if (!token) {
        return reject(new RestError(400, `UnAuthorised User !`));

      }

      AppUser.findOne({
        where: {
          id: token,
          username: username
        }
      })
        .then((userDetails) => {

          if (!userDetails) {
            return reject(new RestError(400, `User not found !`));
          }

          let ipAddress = 'no-ip';
          if (req.headers['x-forwarded-for']) {
            ipAddress = req.headers['x-forwarded-for'];
          }

          if (userDetails) {
            let passwordValidation = decryptPassword(userDetails.password, password);
            if (!passwordValidation) {
              return reject(new RestError(400, `Incorrect Password !`));
            }
          }

          userDetails.ipAddress = ipAddress;

          return userDetails.save();
        })
        .then(resolve)
        .catch(reject);
    });

    if (callback !== null && typeof callback === 'function') {
      promise.then(function (data) { return callback(null, data); }).catch(function (err) { return callback(err); });
    } else {
      return promise;
    }

  };

  AppUser.remoteMethod('login', {
    accepts: [
      {
        arg: 'username',
        type: 'string',
        http: {
          source: 'form'
        }
      },
      {
        arg: 'password',
        type: 'string',
        http: {
          source: 'form'
        }
      },
      {
        arg: 'req',
        type: 'object',
        http: {
          source: 'req'
        }
      }
    ],
    returns: {
      arg: 'data',
      type: 'object',
      root: true
    },
    http: {
      path: '/login',
      verb: 'POST'
    },
    description: 'login'
  });



  AppUser.fetchUserDetails = function (req, callback) {


    const promise = new Promise((resolve, reject) => {

      const token = verifyToken(req);

      if (!token) {
        return reject(new RestError(400, `UnAuthorised User !`));
      }

      AppUser.findOne({
        where: {
          id: token
        }
      })
        .then((userDetails) => {
          if (!userDetails) {
            return reject(new RestError(400, `User not found !`));
          }
          return resolve(userDetails);
        })
        .catch(reject);
    });

    if (callback !== null && typeof callback === 'function') {
      promise.then(function (data) { return callback(null, data); }).catch(function (err) { return callback(err); });
    } else {
      return promise;
    }
  }

  AppUser.remoteMethod('fetchUserDetails', {
    accepts: [
      {
        arg: 'req',
        type: 'object',
        http: {
          source: 'req'
        }
      }
    ],
    returns: {
      arg: 'data',
      type: 'object',
      root: true
    },
    http: {
      path: '/fetchUserDetails',
      verb: 'GET'
    },
    description: 'fetchUserDetails'
  });



  function encryptPassword(password) {

    try {
      let encryptPassword;
      const saltRounds = 10;
      const salt = bcrypt.genSaltSync(saltRounds);
      const passwordHash = bcrypt.hashSync(password, salt);


      encryptPassword = passwordHash;
      console.log(encryptPassword);
      return encryptPassword;
    } catch (error) {
      console.log(error);
    }
  }



  function decryptPassword(oldPassword, newPassword) {
    const isMatch = bcrypt.compare(oldPassword, newPassword);
    if (!isMatch) {
      return true;
    } else {
      return false;
    }
  }



  function verifyToken(req, res, callback) {

    const promise = new Promise((resolve, reject) => {

      const bearerHeader = req.headers["authorization"];
      if (typeof bearerHeader !== "undefined") {
        //Split the header from space
        const bearer = bearerHeader.split(" ");
        //get the token from the array
        const bearerToken = bearer[1];
        //set the token
        req.token = bearerToken;
        //next middleware
        jwt.verify(req.token, JWT_SECRET, (err) => {
          if (err) {
            return reject(new RestError(400, `User UnAutorised!`));
          }
          else {
            let decodedToken = jwtDecode(bearerToken);
            return resolve(decodedToken.sub);
          }
        });
      }
    });

    if (callback !== null && typeof callback === 'function') {
      promise.then(function (data) { return callback(null, data); }).catch(function (err) { return callback(err); });
    } else {
      return promise;
    }
  }

};
