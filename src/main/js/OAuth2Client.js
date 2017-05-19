'use strict';

/**
 * @author palmtale
 * @since 2017/5/18.
 */


import URL from 'url';
import http from 'http';
import https from 'https';
import queryString from 'querystring';

const promisefy = (instance, method) => {
    let methodImpl = method;
    if (_.isString(method)) {
        methodImpl = instance[method];
    }

    return function () { // For find arguments, arrow function is not OK.
        const args = Array.prototype.slice.call(arguments);
        return new Promise((resolve, reject) => {
            args.push((err, ...result) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(result);
                }
            });
            methodImpl.apply(instance, args);
        });
    };
};

const convertBodyAsContentType = (body, headers) => {
    if(!body) {
        headers['Content-length'] = 0;
        return ['', headers];
    }
    const finalHeaders = headers || {};
    let bodyString = '';
    if(!finalHeaders['Content-Type']) {
        finalHeaders['Content-Type'] = 'application/json;charset=utf-8';
    }
    if(finalHeaders['Content-Type'].indexOf('application/json') === 0) {
        bodyString = JSON.stringify(body);
    } else if (finalHeaders['Content-Type'].indexOf('application/x-www-form-urlencoded') === 0) {
        bodyString = queryString.stringify(body);
    }
    finalHeaders['Content-Length'] = Buffer.byteLength(bodyString);
    return [bodyString, finalHeaders];
};

const execute = (http_library, options, post_body, callback) => {
    const allowEarlyClose = options.host && options.host.match(/.*google(apis)?.com$/);

    let callbackCalled = false;

    const request = http_library.request(options);

    const passBackControl = (response, result) => {
        if (!callbackCalled) {
            callbackCalled = true;
            if (!(response.statusCode >= 200 && response.statusCode <= 299) &&
                (response.statusCode !== 301) && (response.statusCode !== 302)) {
                callback({statusCode: response.statusCode, data: result});
            } else {
                callback(null, result, response);
            }
        }
    };

    request.on('response', (response) => {
        let result = '';
        response.on('data', (chunk) => {
            result += chunk;
        });
        response.on('close', () => {
            if (allowEarlyClose) {
                passBackControl(response, result);
            }
        });
        response.addListener('end', () => {
            passBackControl(response, result);
        });
    });

    request.on('error', (e) => {
        callbackCalled = true;
        callback(e);
    });

    if ((options.method === 'POST' || options.method === 'PUT') && post_body) {
        request.write(post_body);
    }

    request.end();
};

const executeAsync = promisefy(null, execute);

export default class OAuth2Client {

    _clientIdName = 'client_id';
    _clientId = null;
    _clientSecretName = 'client_secret';
    _clientSecret = null;
    _urlRoot = '';
    _authorizeUrl = '/oauth/authorize';
    _accessTokenUrl = '/oauth/access_token';

    _accessTokenName = 'access_token';
    _tokenType = 'Bearer';
    _customHeaders = {accept: 'application/json'};
    _authorizationInHeader = false;
    _agent = undefined;

    _responseType = 'code';
    _redirectUri = null;
    _type = '';
    _key = '';

    constructor(clientId, clientSecret, urlRoot, authorizePath, accessTokenPath) {
        if (clientId instanceof Object) {
            this._clientIdName = Object.keys(clientId)[0];
            this._clientId = Object.values(clientId)[0];
        } else {
            this._clientId = clientId;
        }
        if (clientSecret instanceof Object) {
            this._clientSecretName = Object.keys(clientSecret)[0];
            this._clientSecret = Object.values(clientSecret)[0];
        } else {
            this._clientSecret = clientSecret;
        }
        this._urlRoot = urlRoot || '';
        this._authorizeUrl = authorizePath || this._authorizeUrl;
        this._accessTokenUrl = accessTokenPath || this._accessTokenUrl;
    }

    set headers (headers) {
        this._customHeaders = headers;
    }

    addHeader = (key, value) => {
        this._customHeaders[key] = value;
    };

    set responseType(responseType) {
        this._responseType = responseType;
    }

    set clientIdName (clientIdName) {
        this._clientIdName = clientIdName;
    }

    set clientSecretName (clientSecretName) {
        this._clientSecretName = clientSecretName;
    }

    set redirectUri(redirectUri) {
        this._redirectUri = redirectUri;
    }

    set agent(agent) {
        this._agent = agent;
    }

    set accessTokenName(accessTokenName) {
        this._accessTokenName = accessTokenName;
    }

    set tokenType(tokenType) {
        this._tokenType = tokenType;
    }

    set authorizationInHeader(authorizationInHeader) {
        this._authorizationInHeader = authorizationInHeader;
    }

    set type(type) {
        this._type = type;
    }

    get type() {
        return this._type;
    }

    set key(key) {
        this._key = key;
    }

    get key() {
        return this._key;
    }

    get clientId () {
        return this._clientId;
    }

    get authorizeUrl() {
        return this._urlRoot + this._authorizeUrl;
    }

    get accessTokenUrl() {
        return this._urlRoot + this._accessTokenUrl;
    }

    getAccessToken = (token) => {
        return this._tokenType + ' ' + token;
    };

    request = async (method, url, params, body) => {

        const parsedUrl = URL.parse(url, true);
        if (parsedUrl.protocol === 'https:' && !parsedUrl.port) {
            parsedUrl.port = 443;
        }
        const http_library = parsedUrl.protocol === 'https:' ? https : http;
        /** Headers */
        const headers = {};
        for (const key in this._customHeaders) {
            headers[key] = this._customHeaders[key];
        }
        headers['Host'] = parsedUrl.host;
        if (!headers['User-Agent']) {
            headers['User-Agent'] = 'fuxion-oauth2';
        }
        if (this._authorizationInHeader) {
            headers[this._accessTokenName] =
                this.getAccessToken(params.access_token);
        }
        /** QueryString */
        const query = params || {};
        Object.assign(query, parsedUrl.query);
        const queryStr = queryString.stringify(query);
        if (this._authorizationInHeader) {
            delete query[this._accessTokenName];
        }
        const [bodyString, realHeaders]= convertBodyAsContentType(body, headers);
        const options = {
            host: parsedUrl.hostname,
            port: parsedUrl.port,
            path: parsedUrl.pathname + (queryStr ? '?' + queryStr : ''),
            method: method,
            headers: realHeaders
        };
        if (this._agent) {
            options.agent = this._agent;
        }
        return await executeAsync(http_library, options, bodyString);
    };

    getAuthorizeUrl = (params) => {
        const parameters = params || {};
        parameters[this._clientIdName] = this._clientId;
        if (this._redirectUri) {
            parameters['redirect_uri'] = this._redirectUri;
        }
        if (this._responseType) {
            parameters['response_type'] = this._responseType;
        }
        return this.authorizeUrl + '?' + queryString.stringify(parameters);
    };

    getOAuthAccessToken = async (params) => {
        const parameters = params || {};
        parameters[this._clientIdName] = this._clientId;
        parameters[this._clientSecretName] = this._clientSecret;
        if (this._redirectUri) {
            parameters['redirect_uri'] = this._redirectUri;
        }
        if(!params.grant_type) {
            params.grant_type = 'authorization_code';
        }
        if(params.grant_type === 'authorization_code' && !('code' in params)) {
            throw new Error('It\'s required for param `code`');
        }
        if(params.grant_type === 'refresh_token' && !('refresh_token' in params)) {
            throw new Error('It\'s required for param `refresh_token`');
        }
        try {
            const [data, res] = await this.request('POST', this.accessTokenUrl, parameters, parameters);
            return [JSON.parse(data), res];
        }
        catch (e) {
            console.error(e);
        }
    };

    get = async (url, params) => {
        if (!('access_token' in params)) {
            throw new Error('access_token required');
        }
        return await this.request('GET', url, params);
    };

    post = async (url, params, body) => {
        if (!('access_token' in params)) {
            throw new Error('access_token required');
        }
        return await this.request('POST', url, params, body);
    };
}