export interface IRegister {
    (server:any, options:any, next:any): void;
    attributes?: any;
}

export default
class ArkAuth {
    db:any;
    boom:any;
    joi:any;
    bcrypt:any;

    constructor(private mode, private ttl, private env) {
        this.register.attributes = {
            pkg: require('./../../package.json')
        };
        this.boom = require('boom');
        this.joi = require('joi');
        this.bcrypt = require('bcrypt');
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
                    isSecure: false     // Terrible idea but required if not using HTTPS
                });

                server.auth.strategy('facebook', 'bell', this.mode, {
                    provider: 'facebook',
                    password: 'secrect2',
                    clientId: this.env['FACEBOOK_CLIENTID'],
                    clientSecret: this.env['FACEBOOK_CLIENTSECRET'],
                    isSecure: false     // Terrible idea but required if not using HTTPS
                });

                server.auth.default({
                    strategies:['session']
                });

                this.registerRoutes(server, options);


            });


            server.dependency('ark-database', (server, continueRegister) => {
                this.db = server.plugins['ark-database'];
                continueRegister();
                next();
                this._register(server, options);
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
                handler: this.loginHandler
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
                handler: this.loginHandler
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
                        mail: this.joi.string().email().min(3).max(30).required()
                            .description('Mail address'),
                        password: this.joi.string().alphanum().min(3).max(30).required()
                            .description('User set password')
                    }
                }
            }
        });
    }

    loginHandler(request, reply) {
        var profile = request.auth.credentials.profile;
        var strategy = request.auth.strategy;
        this.db.getUserLogin(profile.email, (err, users) => {
            if(err) {
                return reply(this.boom.wrap(err, 400));
            }
            // there is already a user with this email registered
            if(users.length) {
                var user = users[0];
                if(user.value.strategy === strategy) {
                    var userSessionData = {
                        mail: profile.email,
                        _id: user.id
                    };
                    request.auth.session.set(userSessionData);
                    return reply.redirect('/');
                } else {
                    console.log('already registered with another strategy');
                    return reply(this.boom.wrap('email already in use', 409));
                }
            } else {
                console.log('create user');
                var newUser = {
                    mail: profile.email,
                    name: profile.name.first,
                    surname: profile.name.last,
                    picture: 'todo',
                    type: 'user',
                    strategy: strategy
                };

                this.db.createUser(newUser, (err, data) => {
                    if (err) {
                        return reply(this.boom.wrap(err, 400));
                    }
                    var userSessionData = {
                        mail: profile.email,
                        _id: data._id
                    };
                    request.auth.session.set(userSessionData);
                });
            }
        });

    }

    login (request, reply) {
        if (request.auth.isAuthenticated) {
            return reply({ message: 'already authenticated'});
        }
        if(typeof request.payload === 'string') {
            request.payload = JSON.parse(request.payload)
        }

        else {
            this.db.getUserLogin(request.payload.mail, (err, user) => {

                if (err || !user || !user.length) {
                    return reply(this.boom.unauthorized('Wrong/invalid mail or password'));
                }
                this.bcrypt.compare(request.payload.password, user[0].value.password, (err, res) => {
                    console.log('err:', err);
                    console.log('res:', res);
                    if(err || !res) {
                        return reply(this.boom.unauthorized('Wrong/invalid mail or password'));
                    }
                    reply(user[0]);
                    request.auth.session.set(user[0]);
                });

            });

        }
    }

    errorInit(error) {
        if (error) {
            console.log('Error: Failed to load plugin (ArkAuth):', error);
        }
    }
}