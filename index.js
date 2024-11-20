const responser = require('express-responser');
const PromiseFactory = require('logged-promise');
const RequestFactory = require('logged-request-promise');
const isNil = require('lodash/isNil');
const CustomError = require('custom-service-error');
const basicUrl = require('basic-url');

let config;

const validate = (paramsConfig) => {
  if (isNil(paramsConfig.endpoints.authorizeServiceUrl)) throw new Error('express-authorizor validate: Invalid appStart parameters: config.endpoints.authorizeServiceUrl is null or undefined');
};

const validateRole = (role) => {
  if (isNil(role) || role.length <= 0) throw new Error('express-authorizor validateRole: Invalid parameters: role is null or undefined');
};

const validateIsUserArranger = (userId) => {
  if (isNil(userId)) throw new Error('express-authorizor validateRole: Invalid parameters: user is null or undefined');
};

function PermissionError() {
  this.name = 'PermissionError';
  this.message = 'You dont have enough permission';
  this.status = 500;
  this.code = 400105003;
  CustomError.call(this);
}

PermissionError.prototype = CustomError.prototype;
module.exports.PermissionError = PermissionError;

const Authorizor = {};

Authorizor.appStart = (_config) => {
  config = _config;
  validate(config);
};

Authorizor.hasRole = (...roles) => {
  validateRole(roles);
  return (req, res, next) => {
    if (req.currentUser.type === 'OWNER') {
      req.currentUser.hasRole = true;
      req.currentUser.roles = [Authorizor.Admin];

      return next();
    }
    const privateFunctions = Authorizor.init(req.serviceInit);
    privateFunctions.getRoles(roles).then((instances) => {
      req.currentUser.hasRole = true;
      req.currentUser.roles = instances.map(item => item.role);
      return next();
    }).catch((err) => {
      return responser.withError(next, err);
    });
  };
};

Authorizor.isMeOrRole = (...roles) => (req, res, next) => {
  if (req.currentUser.userId.toString() === req.params.user_id) {
    req.currentUser.hasRole = false;
    return next();
  }
  return Authorizor.hasRole(...roles)(req, res, next);
};

Authorizor.isMe = (req, res, next) => {
  if (req.currentUser.userId.toString() === req.params.user_id) {
    req.currentUser.hasRole = false;
    return next();
  }
  return responser.withError(next, new PermissionError());
};

Authorizor.isUserArranger = grant => (req, res, next) => {
  validateIsUserArranger(req.params.user_id);
  if (req.params.user_id.toString() === req.currentUser.userId.toString()) {
    return next();
  }
  if (req.currentUser.type === 'OWNER') {
    req.currentUser.isUserArranger = true;
    return next();
  }
  const privateFunctions = Authorizor.init(req.serviceInit);
  privateFunctions.isUserArranger(req.params.user_id, grant).then(() => {
    req.currentUser.isUserArranger = true;
    return next();
  }).catch((err) => {
    return responser.withError(next, err);
  });
};

Authorizor.init = (serviceInit) => {
  const Request = RequestFactory.init(serviceInit);
  const Promise = PromiseFactory.init(serviceInit);

  return {
    getRoles: (...roles) => {
      return new Promise(roles, (res, rej) => {
        const params = {
          uri: config.endpoints.authorizeServiceUrl,
          method: 'post',
          isAuthenticated: true,
          json: true,
          body: { roles },
          notForwardCross: true,
          crossedUrl: false
        };

        Request(params).then((result) => {
          if (result && Object.keys(result.data).length > 0) {
            return res(result.data);
          }
          return rej(new PermissionError());
        }).catch(() => {
          return rej(new PermissionError());
        });
      });
    },
    isUserArranger: (userId, grant) => new Promise({ userId, grant }, (res, rej) => {
      const params = {
        uri: basicUrl({
          url: config.endpoints.arrangerAuthorizeServiceUrl,
          params: {
            user_id: userId
          }
        }),
        method: 'post',
        isAuthenticated: true,
        json: true,
        body: {
          grant
        },
        notForwardCross: true,
        crossedUrl: false
      };
      Request(params).then((result) => {
        if (result && Object.keys(result.data).length > 0) {
          return res(result.data);
        }
        return rej(new PermissionError());
      }).catch(() => {
        return rej(new PermissionError());
      });
    })
  };
};

Authorizor.Admin = 'Admin';
Authorizor.PowerUser = 'PowerUser';
Authorizor.DataAnalyst = 'DataAnalyst';
Authorizor.GuestArranger = 'GuestArranger';
Authorizor.FlexibleArranger = 'FlexibleArranger';
Authorizor.Arranger = 'Arranger';
Authorizor.SystemDataManager = 'SystemDataManager';
Authorizor.HRMember = 'HRMember';

module.exports = Authorizor;
