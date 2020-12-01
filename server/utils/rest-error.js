'use strict';

const NODE_ENV = process.env.NODE_ENV || 'development';

module.exports = function RestError(status, message, extra) {
  this.name = this.constructor.name;
  this.message = message;
  this.status = status;
  this.extra = extra;

  Error.captureStackTrace(this, this.constructor);
  console.error(this);

  if (NODE_ENV !== 'staging' && NODE_ENV !== 'production') {
    delete this.stack;
  }
};

require('util').inherits(module.exports, Error);
