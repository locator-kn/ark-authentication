export interface IRegister {
    (server:any, options:any, next:any): void;
    attributes?: any;
}

export default
class ArkAuth {
    db:any;
    boom:any;
    joi:any;

    constructor(private mode, private ttl, private env) {
        this.register.attributes = {
            name: 'ark-authentication',
            version: '0.1.0'
        };
        this.boom = require('boom');
        this.joi = require('joi');
    }

    register:IRegister = (server, options, next) => {
        server.bind(this);

        server.register(require('hapi-auth-cookie'), err => {
            if(err) {
                this.errorInit(err);
            }

            //server.auth.strategy('session', 'cookie', this.mode, {
            //    password: 'secret',
            //    ttl: this.ttl || 600000,
            //    keepAlive: true,
            //    cookie: 'ark_session',
            //    isSecure: false
            //});

            server.register(require('bell'), err => {
                if(err) {
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

                server.route({
                    method: ['GET', 'POST'], // Must handle both GET and POST
                    path: '/login',          // The callback endpoint registered with the provider
                    config: {
                        auth: 'google',
                        handler: function (request, reply) {
                            console.log(request.auth)
                            // Perform any account lookup or registration, setup local session,
                            // and redirect to the application. The third-party credentials are
                            // stored in request.auth.credentials. Any query parameters from
                            // the initial request are passed back via request.auth.credentials.query.
                            return reply.redirect('/#/trips');
                        }
                    }
                });

                server.route({
                    method: ['GET', 'POST'], // Must handle both GET and POST
                    path: '/loginFacebook',          // The callback endpoint registered with the provider
                    config: {
                        auth: 'facebook',
                        handler: function (request, reply) {
                            console.log(request.auth);
                            // Perform any account lookup or registration, setup local session,
                            // and redirect to the application. The third-party credentials are
                            // stored in request.auth.credentials. Any query parameters from
                            // the initial request are passed back via request.auth.credentials.query.
                            return reply.redirect('/');
                        }
                    }
                });

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
        // Register
        return 'register';
    }

    errorInit(error) {
        if (error) {
            console.log('Error: Failed to load plugin (ArkAuth):', error);
        }
    }
}