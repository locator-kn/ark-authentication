export interface IRegister {
    (server:any, options:any, next:any): void;
    attributes?: any;
}

declare var Promise:any;

import {initLogging, log, logError} from './util/logging'

export default
class ArkAuth {
    db:any;
    boom:any;
    joi:any;
    bcrypt:any;
    generatePassword:any;
    mailer:any;
    fbgraph:any;

    google:any;
    plus:any;
    oauth2Client:any;

    constructor(private mode, private ttl, private env) {
        this.register.attributes = {
            pkg: require('./../../package.json')
        };
        this.boom = require('boom');
        this.joi = require('joi');
        this.bcrypt = require('bcrypt');
        this.generatePassword = require('password-generator');
        this.fbgraph = require('fbgraph');
        this.google = require('googleapis');

        this.plus = this.google.plus('v1');
        var OAuth2 = this.google.auth.OAuth2;
        this.oauth2Client = new OAuth2(this.env['GOOGLE_CLIENTID'], this.env['GOOGLE_CLIENTSECRET'], 'http://locator-app.com');
    }

    register:IRegister = (server, options, next) => {
        server.bind(this);

        server.register(require('hapi-auth-cookie'), err => {

            if (err) {
                this.errorInit(err);
            }

            server.auth.strategy('session', 'cookie', this.mode, {
                password: this.env['COOKIE_SECRET'],
                ttl: this.ttl || 600000,
                keepAlive: true,
                cookie: 'ark_session',
                isSecure: false,
                clearInvalid: true
            });

            server.register(require('bell'), err => {

                if (err) {
                    this.errorInit(err);
                }

                server.auth.strategy('google', 'bell', this.mode, {
                    provider: 'google',
                    password: 'secrect',
                    clientId: this.env['GOOGLE_CLIENTID'],
                    clientSecret: this.env['GOOGLE_CLIENTSECRET'],
                    isSecure: false,     // Terrible idea but required if not using HTTPS
                    location: 'http://locator-app.com'
                });

                server.auth.strategy('facebook', 'bell', this.mode, {
                    provider: 'facebook',
                    password: 'secrect2',
                    clientId: this.env['FACEBOOK_CLIENTID'],
                    clientSecret: this.env['FACEBOOK_CLIENTSECRET'],
                    isSecure: false,     // Terrible idea but required if not using HTTPS
                    location: 'http://locator-app.com'
                });

                server.auth.default({
                    strategies: ['session']
                });

                this.registerRoutes(server, options);


            });


            server.dependency('ark-database', (server, continueRegister) => {

                this.db = server.plugins['ark-database'];
                continueRegister();
                next();
                this._register(server, options);
            });

            server.dependency('ark-mailer', (server, next) => {
                this.mailer = server.plugins['ark-mailer'];
                next();
            });
        });

        this._register(server, options);
        next();
    };

    private _register(server, options) {

    }

    registerRoutes(server, options) {
        server.route({
            method: ['GET', 'POST'], // Must handle both GET and POST
            path: '/loginGoogle',    // The callback endpoint registered with the provider
            config: {
                auth: {
                    mode: 'try',
                    strategy: 'google'
                },
                handler: this.loginHandler,
                description: 'Login with Google.',
                tags: ['api', 'user', 'auth', 'authentication', 'cookies', 'oauth']
            }
        });

        server.route({
            method: ['GET', 'POST'], // Must handle both GET and POST
            path: '/loginFacebook',          // The callback endpoint registered with the provider
            config: {
                auth: {
                    mode: 'try',
                    strategy: 'facebook'
                },
                handler: this.loginHandler,
                description: 'Login with Facebook.',
                tags: ['api', 'user', 'auth', 'authentication', 'cookies', 'oauth']
            }
        });

        server.route({
            method: ['POST'], // Must handle both GET and POST
            path: '/mobile/loginOAuth',          // The callback endpoint registered with the provider
            config: {
                handler: this.mobileLoginHandler,
                auth: false,
                description: 'Login with Facebook.',
                tags: ['api', 'user', 'mobile', 'auth', 'authentication', 'cookies', 'oauth'],
                validate: {
                    payload: {
                        accessToken: this.joi.string().required()
                            .description('Access token from facebook'),
                        strategy: this.joi.string().required().description('facebook, google')
                    }
                }
            }
        });

        server.route({
            method: ['POST'],
            path: '/login',          // The callback endpoint registered with the provider
            config: {
                auth: {
                    mode: 'try',
                    strategy: 'session'
                },
                handler: this.login,

                description: 'Perform login against backend.',
                tags: ['api', 'user', 'auth', 'authentication', 'cookies'],
                validate: {
                    payload: {
                        mail: this.joi.string().email().min(3).max(60).required()
                            .description('Mail address'),
                        password: this.joi.string().regex(/[a-zA-Z0-9@#$%_&!"§\/\(\)=\?\^]{3,30}/).required()
                            .description('User set password')
                    }
                }
            }
        });

        server.route({
            method: ['GET'],
            path: '/logout',
            config: {
                handler: this.logout,
                description: 'Kill current session.',
                tags: ['api', 'user', 'auth', 'authentication', 'cookies']
            }
        });

        server.route({
            method: ['GET'],
            path: '/users/confirm/{uuid}',
            config: {
                auth: false,
                handler: this.confirm,
                description: 'confirm registration of user by uuid',
                tags: ['api', 'user', 'auth'],
                validate: {
                    params: {
                        uuid: this.joi.string().required()
                    }
                }
            }
        });

        server.route({
            method: ['GET'],
            path: '/forgot/{mail}',
            config: {
                auth: false,
                handler: this.passwordForgotten,
                description: 'send password forgotten mail',
                tags: ['api', 'user', 'auth'],
                validate: {
                    params: {
                        mail: this.joi.string().email().required()
                    }
                }
            }
        });
    }

    _createOrLoginUser(_user:any, strategy, request, reply) {

        this.db.getUserLogin(_user.email)
            .then((user:any) => {
                // there is already a user with this email registered
                if (user.strategy === strategy) {
                    var userSessionData = {
                        mail: user.email,
                        _id: user.id || user._id,
                        name: user.name,
                        strategy: strategy,
                        isAdmin: user.isAdmin || false
                    };
                    request.auth.session.set(userSessionData);
                    return reply(userSessionData);
                } else {
                    return reply(this.boom.conflict('email already taken'));
                }

            }).catch(reason => {
                // this is actually not an error.
                // maybe we should add another db fn which gets resolved if no user is found
                if (reason === 'No user found') {

                    var newUser = {
                        mail: _user.email.toLowerCase(),
                        name: _user.first_name,
                        surname: _user.last_name,
                        strategy: strategy,
                        type: 'user',
                        birthdate: '',
                        residence: '',
                        description: '',
                        verified: true,
                        additionalInfo: _user
                    };

                    request.seneca.act({create: 'user', strategy: strategy, user: newUser}, (err, res) => {

                        if (err) {
                            return reply(err)
                        }

                        // set sessiondata
                        request.auth.session.set({
                            mail: newUser.mail,
                            _id: res.id,
                            strategy: strategy
                        });

                        return reply(res);
                    });
                } else {
                    return reply(this.boom.badRequest(reason));
                }
            });
    }

    mobileLoginGoogle(request, reply) {
        var strategy = 'google';
        // Retrieve tokens via token exchange explained above or set them:
        this.oauth2Client.setCredentials({
            access_token: request.payload.accessToken
        });

        this.plus.people.get({userId: 'me', auth: this.oauth2Client}, (err, response) => {

            if (err || !response.emails || !response.emails.length || !response.emails[0].value) {
                return reply(err || {message: 'missing mail in google oauth'});
            }
            // this is needed because google returns loads of data with a diff structure
            var googleUser = {
                strategy: strategy,
                email: response.emails[0].value,
                picture: response.image.url || '',
                first_name: response.name.givenName || '',
                last_name: response.name.familyName || '',
                raw: response
            };

            this._createOrLoginUser(googleUser, strategy, request, reply);
        });


    }

    mobileLoginFacebook(request, reply) {
        var access_token = request.payload.accessToken;
        var strategy = 'facebook';

        this.fbgraph.setAccessToken(access_token);

        this.fbgraph.get("/me", (err, fb_user) => {
            this._createOrLoginUser(fb_user, strategy, request, reply);
        });
    }

    mobileLoginHandler(request, reply) {
        if (request.payload.strategy === 'facebook') {
            return this.mobileLoginFacebook(request, reply);
        } else {
            return this.mobileLoginGoogle(request, reply);
        }

    }

    /**
     *
     * Handler for authentication via facebook or google.
     * This gets also called if the user is already authenticated and just logs in again.
     *
     * @param request
     * @param reply
     * @returns {any}
     */
    loginHandler(request, reply) {
        if (!request.auth.isAuthenticated) {
            return reply(this.boom.unauthorized('Authentication failed due to: ' + request.auth.error.message));
        }
        var profile = request.auth.credentials.profile;
        var strategy = request.auth.strategy;
        var newUser:any = {};

        this.db.getUserLogin(profile.email)
            .then(user => {

                // there is already a user with this email registered
                if (user.strategy === strategy) {
                    var userSessionData = {
                        mail: profile.email,
                        _id: user.id || user._id,
                        name: user.name,
                        strategy: strategy,
                        isAdmin: user.isAdmin || false
                    };
                    request.auth.session.set(userSessionData);
                    return reply.redirect('/#/context');
                } else {
                    return reply.redirect('/#/error?r=emailTaken');
                }
            }).catch(reason => {
                // this is actually not an error.
                // maybe we should add another db fn which gets resolved if no user is found
                if (reason === 'No user found') {

                    // Sorry for that, i gonna refactor all the things after launch, maybe
                    if (profile.strategy !== 'facebook') {

                        newUser = {
                            mail: profile.email.toLowerCase(),
                            name: profile.name.first,
                            surname: profile.name.last,
                            picture: profile.raw.picture || '',
                            strategy: strategy,
                            type: 'user',
                            birthdate: '',
                            residence: '',
                            description: '',
                            verified: true,
                            additionalInfo: request.auth.credentials
                        };

                    } else {

                        newUser = profile;
                    }

                    request.seneca.act({create: 'user', strategy: profile.strategy, user: newUser}, (err, res) => {

                        if (err) {
                            return reply(err)
                        }

                        // set sessiondata
                        request.auth.session.set({
                            mail: newUser.mail,
                            _id: res.id,
                            strategy: strategy
                        });

                        return reply(res);
                        // redirect to context, this route takes the user back to where he was
                        reply.redirect('/#/context');
                    });

                } else {
                    return reply(this.boom.badRequest(reason));
                }
            })


    }

    login(request, reply) {
        var b = this.boom;
        if (request.auth.isAuthenticated) {
            return reply({message: 'already authenticated'});
        }

        function replySuccess() {
            reply({
                message: 'Hi there'
            });
        }

        function replyUnauthorized(reason) {
            if (!reason) {
                reason = 'Wrong/invalid mail or password';
            }
            reply(b.unauthorized(reason));
        }


        this.db.getUserLogin(request.payload.mail.toLowerCase())
            .then(user => {

                let setSessionData = () => {
                    request.auth.session.set({
                        _id: user._id,
                        mail: user.mail,
                        name: user.name,
                        strategy: user.strategy,
                        isAdmin: user.isAdmin || false
                    });
                };

                this.comparePassword(request.payload.password, user.password)
                    .then(setSessionData)
                    .then(replySuccess)
                    .catch(() => {

                        this.checkForResetPassword(user)
                            .then(()=> {
                                return this.compareResetPassword(request.payload.password, user);
                            })
                            .then((user) => {
                                return this.resetUserPassword(user);
                            })
                            .then(setSessionData)
                            .then(replySuccess)
                            .catch(replyUnauthorized);
                    })


            }).catch(replyUnauthorized);
    }

    comparePassword(plain:string, password) {
        return new Promise((resolve, reject) => {
            this.bcrypt.compare(plain, password, (err, res) => {
                if (err || !res) {
                    return reject(err || 'Wrong/invalid mail or password');
                }
                resolve(res);
            });
        });
    }

    compareResetPassword(plain:string, user) {
        return new Promise((resolve, reject) => {
            this.bcrypt.compare(plain, user.resetPasswordToken, (err, res) => {
                if (err || !res) {
                    return reject(err || 'Wrong/invalid mail or password');
                }
                resolve(user);
            });
        });
    }

    checkForResetPassword(user) {
        return new Promise((resolve, reject) => {
            if (user.resetPasswordToken && user.resetPasswordExpires) {
                var currentTimestamp = Date.now();
                // check if password token not older than 5 hours
                if (((currentTimestamp - user.resetPasswordExpires) / 60e3) < 300) { // 5 hours
                    return resolve();
                }
            }
            reject();
        });
    }

    resetUserPassword(user) {
        // set temporary password to new password
        user.password = user.resetPasswordToken;
        // 'disable' reset password tokens
        user.resetPasswordToken = null;
        user.resetPasswordExpires = null;

        return this.db.updateUser(user._id, user);
    }

    logout(request, reply) {
        request.auth.session.clear();
        reply({
            message: 'bye bye'
        });
    }

    confirm = (request, reply)=> {
        this.db.getUserByUUID(request.params.uuid)
            .then(user => {
                if (!user.verified) {
                    reply(this.db.updateUser(user._id, {verified: true}));
                    // TODO: redirect user to landing page
                } else {
                    reply(this.boom.badRequest('Mail already verified!'));
                }
            }).catch(reply)
    };


    /**
     * Function to call if user forget his password.
     * @param request
     * @param reply
     */
    passwordForgotten = (request, reply) => {
        var _user;
        var resetPassword;

        this.db.getUserLogin(request.params.mail.toLowerCase())
            .then(user => {
                _user = user;
                resetPassword = this.generatePassword(12, false);
                return this.generatePasswordToken(resetPassword);
            }).then(hash => {
                _user.resetPasswordToken = hash;
                return this.updatePasswordToken(_user);
            }).then(() => {

                this.sendMail({
                    mail: _user.mail,
                    name: _user.name,
                    resetPassword: resetPassword
                });

                reply({
                    message: 'New password generated and sent per mail.'
                });

            }).catch(err => {
                if (err.isBoom) {
                    return reply(err);
                }
                reply(this.boom.badRequest(err))
            });
    };

    // TODO: maybe extract to a global utility package
    generatePasswordToken(password) {
        return new Promise((resolve, reject) => {

            this.bcrypt.genSalt(10, (err, salt) => {

                if (err) {
                    return reject(err);
                }
                this.bcrypt.hash(password, salt, (err, hash) => {

                    if (err) {
                        return reject(err);
                    }
                    resolve(hash)
                })
            })
        });
    }

    sendMail = (user) => {
        // send mail to user with new password token
        this.mailer.sendPasswordForgottenMail(user);
    };

    updatePasswordToken = (user) => {
        // set timestamp for password expires
        user.resetPasswordExpires = Date.now();

        // update user with new value
        return this.db.updateUser(user._id, user);
    };


    errorInit(error) {
        if (error) {
            logError('Error: Failed to load plugin (ArkAuth):' + error);
        }
    }
}
