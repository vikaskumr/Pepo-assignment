'use strict';

const app = require('../server.js');
const _ = require('underscore');
const async = require('async');

new Promise(function (resolve, reject) {
  app.models.FileStorageContainer.getContainers(function (err, containers) {
    if (err) {
      return reject(err);
    }
    return resolve(containers);
  });
})
  .then(function (containers) {
    let promises = [];
    _.each(app.models.FileStorageContainer.containers, function (containerDefinition) {
      if (_.pluck(containers, 'name').indexOf(containerDefinition.name) == -1) {
        promises.push(new Promise(function (resolve, reject) {
          app.models.FileStorageContainer.createContainer({ name: containerDefinition.name }, function (err) {
            if (err) {
              return reject(err);
            }
            return resolve();
          });
        }));
        console.log('Creating container ' + containerDefinition.name);
      }
    });
    return Promise.all(promises);
  })
  .then(function () {
    console.log('File containers migrated successfully');
    process.exit(0);
  })
  .catch(function (error) {
    console.error(error);
    process.exit(1);
  });
