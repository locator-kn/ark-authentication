export interface IRegister {
    (server:any, options:any, next:any): void;
    attributes?: any;
}

declare
var Promise:any;

export default
class ArkAuth {
    db:any;
    boom:any;
    joi:any;
    bcrypt:any;
    generatePassword:any;
    mailer:any;

    constructor(private mode, private ttl, private env) {
        this.register.attributes = {
            pkg: require('./../../package.json')
        };
        this.boom = require('boom');
        this.joi = require('joi');
        this.bcrypt = require('bcrypt');
        this.generatePassword = require('password-generator');
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
                isSecure: false
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
                    location: 'http://locator-app.com/api/v1/loginGoogle'
                });

                server.auth.strategy('facebook', 'bell', this.mode, {
                    provider: 'facebook',
                    password: 'secrect2',
                    clientId: this.env['FACEBOOK_CLIENTID'],
                    clientSecret: this.env['FACEBOOK_CLIENTSECRET'],
                    isSecure: false,     // Terrible idea but required if not using HTTPS
                    location: 'http://locator-app.com/api/v1/loginFacebook'
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
                tags: ['api', 'user', 'auth']
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
                        mail: this.joi.string()
                            .required()
                    }
                }
            }
        });
    }

    loginHandler(request, reply) {
        var profile = request.auth.credentials.profile;
        var strategy = request.auth.strategy;

        this.db.getUserLogin(profile.email)
            .then(user => {

                // there is already a user with this email registered
                if (user.strategy === strategy) {
                    var userSessionData = {
                        mail: profile.email,
                        _id: user.id,
                        name: user.name,
                        strategy: strategy,
                        isAdmin: user.isAdmin || false
                    };
                    request.auth.session.set(userSessionData);
                    // TODO: set relative in production
                    return reply.redirect('http://localhost:8000/#/context');
                } else {
                    return reply(this.boom.conflict('email already in use'));
                }
            }).catch(reason => {

                if (reason === 'No user found') {
                    var newUser = {
                        mail: profile.email.toLowerCase(),
                        name: profile.name.first,
                        surname: profile.name.last,
                        picture: {
                            picture: profile.raw.picture, // TODO: is raw defined?? google? facebook?
                            thumbnail: profile.raw.picture
                        },
                        strategy: strategy,
                        type: 'user',
                        birthdate: '',
                        residence: '',
                        description: '',
                        verified: false, // TODO: or true? will he get a mail??
                        additionalInfo: request.auth.credentials
                    };

                    this.db.createUser(newUser, (err, data) => {

                        if (err) {
                            return reply(this.boom.badRequest(err));
                        }
                        var userSessionData = {
                            mail: profile.email,
                            _id: data._id,
                            name: data.name,
                            strategy: strategy
                        };
                        request.auth.session.set(userSessionData);
                        // TODO: set relative in production
                        return reply.redirect('http://localhost:8000/#/context');
                    });
                } else {
                    return reply(this.boom.badRequest(reason));
                }

            });
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
        return new Promise((resolve, reject) => {
            // set temporary password to new password
            user.password = user.resetPasswordToken;
            // 'disable' reset password tokens
            user.resetPasswordToken = null;
            user.resetPasswordExpires = null;
            this.db.updateUser(user._id, user, (err, data) => {
                if (err) {
                    return reject(err);
                }
            });
            resolve();
        });
    }

    logout(request, reply) {
        request.auth.session.clear();
        reply({
            message: 'bye bye'
        });
    }

    confirm(request, reply) {
        this.db.getUserByUUID(request.params.uuid, (err, data)=> {

            if (err) {
                return reply(this.boom.badRequest('Error on confirmation of e-mail address '));
            }

            var user = data;
            if (!user.verified) {
                reply(this.db.updateDocument(user._id, {verified: true}));
            } else {
                reply(this.boom.badRequest('Mail already verified!'));
            }
        })
    }

    /**
     * Function to call if user forget his password.
     * @param request
     * @param reply
     */
    passwordForgotten = (request, reply) => {
        this.db.getUserLogin(request.params.mail.toLowerCase())
            .then(user => {

                function replySuccess() {
                    reply({
                        message: 'New password generated and sent per mail.'
                    });
                }

                return this.generatePasswordToken(user)
                    .then(this.updatePasswordToken)
                    .then(this.sendMail)
                    .then(replySuccess)

            }).catch(err => reply(this.boom.badRequest(err)));
    };

    generatePasswordToken(user) {
        return new Promise((resolve, reject) => {
            // generate reset password
            var resetPassword = this.generatePassword(12, false); // -> 76PAGEaq6i5c

            this.bcrypt.genSalt(10, (err, salt) => {
                this.bcrypt.hash(resetPassword, salt, (err, hash) => {
                    if (err) {
                        return reject(err);
                    }
                    user.resetPasswordToken = hash;
                    user.resetPassword = resetPassword;
                    resolve(user)
                })
            })

        });
    }

    sendMail = (user) => {
        // send mail to user with new password token
        this.mailer.sendPasswordForgottenMail(user);
    };

    updatePasswordToken = (user) => {
        return new Promise((resolve, reject) => {
            // set timestamp for password expires
            user.resetPasswordExpires = Date.now();
            // tmp remove of plain text variable
            var resetPassword = user.resetPassword;
            delete user.resetPassword;
            // update user with new value
            this.db.updateUser(user._id, user, (err, data) => {
                if (err) {
                    return reject(err);
                }
                // add plain text variable for email
                user.resetPassword = resetPassword;
                resolve(user);
            });
        });
    };


    errorInit(error) {
        if (error) {
            console.log('Error: Failed to load plugin (ArkAuth):', error);
        }
    }
}
