var server;

export function initLogging(hapiServer:any) {
    server = hapiServer;
}


export function log(logging:string) {
    if (!server) {
        console.error('Server not initialized for logging');
        return;
    }

    server.log(['authentication'],logging);
}

export function logError(logging:string) {
    if (!server) {
        console.error('Server not initialized for logging');
        return;
    }

    server.log(['authentication', 'Error'],logging);
}
