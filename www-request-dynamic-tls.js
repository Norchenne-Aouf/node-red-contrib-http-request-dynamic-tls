/**
 * Copyright JS Foundation and other contributors, http://js.foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = async function (RED) {
    "use strict";
    const { got } = await import('got')
    const { CookieJar } = require("tough-cookie");
    const { HttpProxyAgent, HttpsProxyAgent } = require('hpagent');
    const FormData = require('form-data');
    const { v4: uuid } = require('uuid');
    const crypto = require('crypto');
    const URL = require("url").URL
    const http = require("http")
    const https = require("https")
    var mustache = require("mustache");
    var querystring = require("querystring");
    var cookie = require("cookie");
    var hashSum = require("hash-sum");
    const jschardet = require('jschardet');

    /********************************************************PROXY HELPER */
    /**
 * Parse a URL into its components.
 * @param {String} url The URL to parse
 * @returns {URL}
 */
    const parseUrl = (url) => {
        let parsedUrl = {
            protocol: null,
            host: null,
            port: null,
            hostname: null,
            query: null,
            href: null
        }
        try {
            if (!url) { return parsedUrl }
            parsedUrl = new URL(url)
        } catch (error) {
            // dont throw error
        }
        return parsedUrl
    }

    const DEFAULT_PORTS = {
        ftp: 21,
        gopher: 70,
        http: 80,
        https: 443,
        ws: 80,
        wss: 443,
        mqtt: 1880,
        mqtts: 8883
    }

    const modeOverride = getEnv('NR_PROXY_MODE', {})

    /**
     * @typedef {Object} ProxyOptions
     * @property {'strict'|'legacy'} [mode] - Legacy mode is for non-strict previous proxy determination logic (for node-red <= v3.1 compatibility) (default 'strict')
     * @property {boolean} [favourUpperCase] - Favour UPPER_CASE *_PROXY env vars (default false)
     * @property {boolean} [lowerCaseOnly] - Prevent UPPER_CASE *_PROXY env vars being used. (default false)
     * @property {boolean} [excludeNpm] - Prevent npm_config_*_proxy env vars being used. (default false)
     * @property {object} [env] - The environment object to use (defaults to process.env)
     */

    /**
     * Get the proxy URL for a given URL.
     * @param {string|URL} url - The URL, or the result from url.parse.
     * @param {ProxyOptions} [options] - The options object (optional)
     * @return {string} The URL of the proxy that should handle the request to the
     *  given URL. If no proxy is set, this will be an empty string.
     */
    function getProxyForUrl(url, options) {
        url = url || ''
        const defaultOptions = {
            mode: 'strict',
            lowerCaseOnly: false,
            favourUpperCase: false,
            excludeNpm: false,
        }
        options = Object.assign({}, defaultOptions, options)

        if (modeOverride === 'legacy' || modeOverride === 'strict') {
            options.mode = modeOverride
        }

        if (options.mode === 'legacy') {
            return legacyGetProxyForUrl(url, options.env || process.env)
        }

        const parsedUrl = typeof url === 'string' ? parseUrl(url) : url || {}
        let proto = parsedUrl.protocol
        let hostname = parsedUrl.host
        let port = parsedUrl.port
        if (typeof hostname !== 'string' || !hostname || typeof proto !== 'string') {
            return ''  // Don't proxy URLs without a valid scheme or host.
        }

        proto = proto.split(':', 1)[0]
        // Stripping ports in this way instead of using parsedUrl.hostname to make
        // sure that the brackets around IPv6 addresses are kept.
        hostname = hostname.replace(/:\d*$/, '')
        port = parseInt(port) || DEFAULT_PORTS[proto] || 0
        if (!shouldProxy(hostname, port, options)) {
            return ''  // Don't proxy URLs that match NO_PROXY.
        }

        let proxy =
            getEnv('npm_config_' + proto + '_proxy', options) ||
            getEnv(proto + '_proxy', options) ||
            getEnv('npm_config_proxy', options) ||
            getEnv('all_proxy', options)
        if (proxy && proxy.indexOf('://') === -1) {
            // Missing scheme in proxy, default to the requested URL's scheme.
            proxy = proto + '://' + proxy
        }
        return proxy
    }

    /**
     * Get the proxy URL for a given URL.
     * For node-red < v3.1 or compatibility mode
     * @param {string} url The URL to check for proxying
     * @param {object} [env] The environment object to use (default process.env)
     * @returns 
     */
    function legacyGetProxyForUrl(url, env) {
        env = env || process.env
        let prox, noprox;
        if (env.http_proxy) { prox = env.http_proxy; }
        if (env.HTTP_PROXY) { prox = env.HTTP_PROXY; }
        if (env.no_proxy) { noprox = env.no_proxy.split(","); }
        if (env.NO_PROXY) { noprox = env.NO_PROXY.split(","); }

        let noproxy = false;
        if (noprox) {
            for (let i in noprox) {
                if (url.indexOf(noprox[i].trim()) !== -1) { noproxy = true; }
            }
        }
        if (prox && !noproxy) {
            return prox
        }
        return ""
    }

    /**
     * Determines whether a given URL should be proxied.
     *
     * @param {string} hostname - The host name of the URL.
     * @param {number} port - The effective port of the URL.
     * @returns {boolean} Whether the given URL should be proxied.
     * @private
     */
    function shouldProxy(hostname, port, options) {
        const NO_PROXY =
            (getEnv('npm_config_no_proxy', options) || getEnv('no_proxy', options)).toLowerCase()
        if (!NO_PROXY) {
            return true  // Always proxy if NO_PROXY is not set.
        }
        if (NO_PROXY === '*') {
            return false  // Never proxy if wildcard is set.
        }

        return NO_PROXY.split(/[,\s]/).every(function (proxy) {
            if (!proxy) {
                return true  // Skip zero-length hosts.
            }
            const parsedProxy = proxy.match(/^(.+):(\d+)$/)
            let parsedProxyHostname = parsedProxy ? parsedProxy[1] : proxy
            const parsedProxyPort = parsedProxy ? parseInt(parsedProxy[2]) : 0
            if (parsedProxyPort && parsedProxyPort !== port) {
                return true  // Skip if ports don't match.
            }

            if (!/^[.*]/.test(parsedProxyHostname)) {
                // No wildcards, so stop proxying if there is an exact match.
                return hostname !== parsedProxyHostname
            }

            if (parsedProxyHostname.charAt(0) === '*') {
                // Remove leading wildcard.
                parsedProxyHostname = parsedProxyHostname.slice(1)
            }
            // Stop proxying if the hostname ends with the no_proxy host.
            return !hostname.endsWith(parsedProxyHostname)
        })
    }

    /**
     * Get the value for an environment constiable.
     *
     * @param {string} key - The name of the environment constiable.
     * @param {ProxyOptions} options - The name of the environment constiable.
     * @return {string} The value of the environment constiable.
     * @private
     */
    function getEnv(key, options) {
        const env = (options && options.env) || process.env
        if (options && options.excludeNpm === true) {
            if (key.startsWith('npm_config_')) {
                return ''
            }
        }
        if (options && options.lowerCaseOnly === true) {
            return env[key.toLowerCase()] || ''
        } else if (options && options.favourUpperCase === true) {
            return env[key.toUpperCase()] || env[key.toLowerCase()] || ''
        }
        return env[key.toLowerCase()] || env[key.toUpperCase()] || ''
    }

    /******************************************************************** */

    // Cache a reference to the existing https.request function
    // so we can compare later to see if an old agent-base instance
    // has been required.
    // This is generally okay as the core nodes are required before
    // any contrib nodes. Where it will fail is if the agent-base module
    // is required via the settings file or outside of Node-RED before it
    // is started.
    // If there are other modules that patch the function, they will get undone
    // as well. Not much we can do about that right now. Patching core
    // functions is bad.
    const HTTPS_MODULE = require("https");
    const HTTPS_REQUEST = HTTPS_MODULE.request;

    function checkNodeAgentPatch() {
        if (HTTPS_MODULE.request !== HTTPS_REQUEST && HTTPS_MODULE.request.length === 2) {
            RED.log.warn(`

---------------------------------------------------------------------
Patched https.request function detected. This will break the
HTTP Request node. The original code has now been restored.

This is likely caused by a contrib node including an old version of
the 'agent-base@<5.0.0' module.

You can identify what node is at fault by running:
   npm list agent-base
in your Node-RED user directory (${RED.settings.userDir}).
---------------------------------------------------------------------
`);
            HTTPS_MODULE.request = HTTPS_REQUEST
        }
    }

    function HTTPRequest(n) {
        RED.nodes.createNode(this, n);
        checkNodeAgentPatch();
        const node = this;
        const nodeUrl = n.url;
        const isTemplatedUrl = (nodeUrl || "").indexOf("{{") != -1;
        const nodeMethod = n.method || "GET";
        let paytoqs = false;
        let paytobody = false;
        let redirectList = [];
        const sendErrorsToCatch = n.senderr;
        node.headers = n.headers || [];
        const useKeepAlive = n.persist;
        let agents = null
        if (useKeepAlive) {
            agents = {
                http: new http.Agent({ keepAlive: true }),
                https: new https.Agent({ keepAlive: true })
            }
            node.on('close', function () {
                agents.http.destroy()
                agents.https.destroy()
            })
        }
        if (n.tls) {
            var tlsNode = RED.nodes.getNode(n.tls);
        }
        this.ret = n.ret || "txt";

        this.authType = n.authType || "basic";
        if (RED.settings.httpRequestTimeout) { this.reqTimeout = parseInt(RED.settings.httpRequestTimeout) || 120000; }
        else { this.reqTimeout = 120000; }

        if (n.paytoqs === true || n.paytoqs === "query") { paytoqs = true; }
        else if (n.paytoqs === "body") { paytobody = true; }

        node.insecureHTTPParser = n.insecureHTTPParser

        let proxyConfig = n.proxy ? RED.nodes.getNode(n.proxy) || {} : null
        const getProxy = (url) => {
            const proxyOptions = Object.assign({}, RED.settings.proxyOptions);
            if (n.proxy && proxyConfig) {
                proxyOptions.env = {
                    no_proxy: (proxyConfig.noproxy || []).join(','),
                    http_proxy: (proxyConfig.url),
                    https_proxy: (proxyConfig.url)
                }
            }
            return getProxyForUrl(url, proxyOptions)
        }
        let prox = nodeUrl ? getProxy(nodeUrl) : null

        let timingLog = false;
        if (RED.settings.hasOwnProperty("httpRequestTimingLog")) {
            timingLog = RED.settings.httpRequestTimingLog;
        }

        /**
         * Case insensitive header value update util function
         * @param {object} headersObject The opt.headers object to update
         * @param {string} name The header name
         * @param {string} value The header value to set (if blank, header is removed)
         */
        const updateHeader = function (headersObject, name, value) {
            const hn = name.toLowerCase();
            const keys = Object.keys(headersObject);
            const matchingKeys = keys.filter(e => e.toLowerCase() == hn)
            const updateKey = (k, v) => {
                delete headersObject[k]; //delete incase of case change
                if (v) { headersObject[name] = v } //re-add with requested name & value
            }
            if (matchingKeys.length == 0) {
                updateKey(name, value)
            } else {
                matchingKeys.forEach(k => {
                    updateKey(k, value);
                });
            }
        }
        /**
         * @param {Object} headersObject
         * @param {string} name
         * @return {any} value
        */
        const getHeaderValue = (headersObject, name) => {
            const asLowercase = name.toLowercase();
            return headersObject[Object.keys(headersObject).find(k => k.toLowerCase() === asLowercase)];
        }
        this.on("input", async function (msg, nodeSend, nodeDone) {
            checkNodeAgentPatch();
            //reset redirectList on each request
            redirectList = [];
            var preRequestTimestamp = process.hrtime();
            node.status({ fill: "blue", shape: "dot", text: "httpin.status.requesting" });
            var url = nodeUrl || msg.url;
            if (msg.url && nodeUrl && (nodeUrl !== msg.url)) {  // revert change below when warning is finally removed
                node.warn(RED._("common.errors.nooverride"));
            }

            if (isTemplatedUrl) {
                url = mustache.render(nodeUrl, msg);
            }
            if (!url) {
                node.error(RED._("httpin.errors.no-url"), msg);
                nodeDone();
                return;
            }


            // url must start http:// or https:// so assume http:// if not set
            if (url.indexOf("://") !== -1 && url.indexOf("http") !== 0) {
                node.warn(RED._("httpin.errors.invalid-transport"));
                node.status({ fill: "red", shape: "ring", text: "httpin.errors.invalid-transport" });
                nodeDone();
                return;
            }
            if (!((url.indexOf("http://") === 0) || (url.indexOf("https://") === 0))) {
                if (tlsNode) {
                    url = "https://" + url;
                } else {
                    url = "http://" + url;
                }
            }
            // before any parameters are appended to the `url`, lets check see if the proxy needs a refresh
            let proxyUrl = prox; // The proxyUrl determined for `nodeUrl`
            if (url !== nodeUrl) {
                proxyUrl = getProxy(url)
            }
            // The Request module used in Node-RED 1.x was tolerant of query strings that
            // were partially encoded. For example - "?a=hello%20there&b=20%"
            // The GOT module doesn't like that.
            // The following is an attempt to normalise the url to ensure it is properly
            // encoded. We cannot just encode it directly as we don't want any valid
            // encoded entity to end up doubly encoded.
            if (url.indexOf("?") > -1) {
                // Only do this if there is a query string to deal with
                const [hostPath, ...queryString] = url.split("?")
                const query = queryString.join("?");
                if (query) {
                    // Look for any instance of % not followed by two hex chars.
                    // Replace any we find with %25.
                    const escapedQueryString = query.replace(/(%.?.?)/g, function (v) {
                        if (/^%[a-f0-9]{2}/i.test(v)) {
                            return v;
                        }
                        return v.replace(/%/, "%25")
                    })
                    url = hostPath + "?" + escapedQueryString;
                }
            }

            var method = nodeMethod.toUpperCase() || "GET";
            if (msg.method && n.method && (n.method !== "use")) {     // warn if override option not set
                node.warn(RED._("common.errors.nooverride"));
            }
            if (msg.method && n.method && (n.method === "use")) {
                method = msg.method.toUpperCase();          // use the msg parameter
            }

            // var isHttps = (/^https/i.test(url));

            var opts = {};
            // set defaultport, else when using HttpsProxyAgent, it's defaultPort of 443 will be used :(.
            // Had to remove this to get http->https redirect to work
            // opts.defaultPort = isHttps?443:80;
            opts.timeout = { request: node.reqTimeout || 5000 };
            opts.throwHttpErrors = false;
            // TODO: add UI option to auto decompress. Setting to false for 1.x compatibility
            opts.decompress = false;
            opts.method = method;
            opts.retry = { limit: 0 };
            opts.responseType = 'buffer';
            opts.maxRedirects = 21;
            opts.cookieJar = new CookieJar();
            opts.ignoreInvalidCookies = true;
            // opts.forever = nodeHTTPPersistent;
            if (msg.requestTimeout !== undefined) {
                if (isNaN(msg.requestTimeout)) {
                    node.warn(RED._("httpin.errors.timeout-isnan"));
                } else if (msg.requestTimeout < 1) {
                    node.warn(RED._("httpin.errors.timeout-isnegative"));
                } else {
                    opts.timeout = { request: msg.requestTimeout };
                }
            }
            const originalHeaderMap = {};

            opts.hooks = {
                beforeRequest: [
                    options => {
                        // Whilst HTTP headers are meant to be case-insensitive,
                        // in the real world, there are servers that aren't so compliant.
                        // GOT will lower case all headers given a chance, so we need
                        // to restore the case of any headers the user has set.
                        Object.keys(options.headers).forEach(h => {
                            if (originalHeaderMap[h] && originalHeaderMap[h] !== h) {
                                options.headers[originalHeaderMap[h]] = options.headers[h];
                                delete options.headers[h];
                            }
                        })
                        if (node.insecureHTTPParser) {
                            // Setting the property under _unixOptions as pretty
                            // much the only hack available to get got to apply
                            // a core http option it doesn't think we should be
                            // allowed to set
                            options._unixOptions = { ...options.unixOptions, insecureHTTPParser: true }
                        }
                    }
                ],
                beforeRedirect: [
                    (options, response) => {
                        let redirectInfo = {
                            location: response.headers.location
                        }
                        if (response.headers.hasOwnProperty('set-cookie')) {
                            redirectInfo.cookies = extractCookies(response.headers['set-cookie']);
                        }
                        redirectList.push(redirectInfo)
                    }
                ]
            }

            let ctSet = "Content-Type"; // set default camel case
            let clSet = "Content-Length";
            const normaliseKnownHeader = function (name) {
                const _name = name.toLowerCase();
                // only normalise the known headers used later in this
                // function. Otherwise leave them alone.
                switch (_name) {
                    case "content-type":
                    case "content-length":
                        ctSet = name;
                        name = _name;
                        break;
                }
                return name;
            }

            opts.headers = {};
            //add msg.headers
            //NOTE: ui headers will take precidence over msg.headers
            if (msg.headers) {
                if (msg.headers.hasOwnProperty('x-node-red-request-node')) {
                    const headerHash = msg.headers['x-node-red-request-node'];
                    delete msg.headers['x-node-red-request-node'];
                    const hash = hashSum(msg.headers);
                    if (hash === headerHash) {
                        delete msg.headers;
                    }
                }
                if (msg.headers) {
                    for (let hn in msg.headers) {
                        const name = normaliseKnownHeader(hn);
                        updateHeader(opts.headers, name, msg.headers[hn]);
                    }
                }
            }

            //add/remove/update headers from UI.
            if (node.headers.length) {
                for (let index = 0; index < node.headers.length; index++) {
                    const header = node.headers[index];
                    let headerName, headerValue;
                    if (header.keyType === "other") {
                        headerName = header.keyValue
                    } else if (header.keyType === "msg") {
                        RED.util.evaluateNodeProperty(header.keyValue, header.keyType, node, msg, (err, value) => {
                            if (err) {
                                //ignore header
                            } else {
                                headerName = value;
                            }
                        });
                    } else {
                        headerName = header.keyType
                    }
                    if (!headerName) {
                        continue; //skip if header name is empyy
                    }
                    if (header.valueType === "other") {
                        headerValue = header.valueValue
                    } else if (header.valueType === "msg") {
                        RED.util.evaluateNodeProperty(header.valueValue, header.valueType, node, msg, (err, value) => {
                            if (err) {
                                //ignore header
                            } else {
                                headerValue = value;
                            }
                        });
                    } else {
                        headerValue = header.valueType
                    }
                    const hn = normaliseKnownHeader(headerName);
                    updateHeader(opts.headers, hn, headerValue);
                }
            }


            if (msg.hasOwnProperty('followRedirects')) {
                opts.followRedirect = !!msg.followRedirects;
            }

            if (opts.headers.hasOwnProperty('cookie')) {
                var cookies = cookie.parse(opts.headers.cookie, { decode: String });
                for (var name in cookies) {
                    opts.cookieJar.setCookieSync(cookie.serialize(name, cookies[name], { encode: String }), url, { ignoreError: true });
                }
                delete opts.headers.cookie;
            }
            if (msg.cookies) {
                for (var name in msg.cookies) {
                    if (msg.cookies.hasOwnProperty(name)) {
                        if (msg.cookies[name] === null || msg.cookies[name].value === null) {
                            // This case clears a cookie for HTTP In/Response nodes.
                            // Ignore for this node.
                        } else if (typeof msg.cookies[name] === 'object') {
                            if (msg.cookies[name].encode === false) {
                                // If the encode option is false, the value is not encoded.
                                opts.cookieJar.setCookieSync(cookie.serialize(name, msg.cookies[name].value, { encode: String }), url, { ignoreError: true });
                            } else {
                                // The value is encoded by encodeURIComponent().
                                opts.cookieJar.setCookieSync(cookie.serialize(name, msg.cookies[name].value), url, { ignoreError: true });
                            }
                        } else {
                            opts.cookieJar.setCookieSync(cookie.serialize(name, msg.cookies[name]), url, { ignoreError: true });
                        }
                    }
                }
            }
            var parsedURL = new URL(url)
            this.credentials = this.credentials || {}
            if (parsedURL.username && !this.credentials.user) {
                this.credentials.user = parsedURL.username
            }
            if (parsedURL.password && !this.credentials.password) {
                this.credentials.password = parsedURL.password
            }
            if (Object.keys(this.credentials).length != 0) {
                if (this.authType === "basic") {
                    // Workaround for https://github.com/sindresorhus/got/issues/1169 (fixed in got v12)
                    // var cred = ""
                    if (this.credentials.user || this.credentials.password) {
                        // cred = `${this.credentials.user}:${this.credentials.password}`;
                        if (this.credentials.user === undefined) { this.credentials.user = "" }
                        if (this.credentials.password === undefined) { this.credentials.password = "" }
                        opts.headers.Authorization = "Basic " + Buffer.from(`${this.credentials.user}:${this.credentials.password}`).toString("base64");
                    }
                    // build own basic auth header
                    // opts.headers.Authorization = "Basic " + Buffer.from(cred).toString("base64");
                } else if (this.authType === "digest") {
                    let digestCreds = this.credentials;
                    let sentCreds = false;
                    opts.hooks.afterResponse = [(response, retry) => {
                        if (response.statusCode === 401) {
                            if (sentCreds) {
                                return response
                            }
                            const requestUrl = new URL(response.request.requestUrl);
                            const options = { headers: {} }
                            const normalisedHeaders = {};
                            Object.keys(response.headers).forEach(k => {
                                normalisedHeaders[k.toLowerCase()] = response.headers[k]
                            })
                            if (normalisedHeaders['www-authenticate']) {
                                let authHeader = buildDigestHeader(digestCreds.user, digestCreds.password, response.request.options.method, requestUrl.pathname, normalisedHeaders['www-authenticate'])
                                options.headers.Authorization = authHeader;
                            }
                            // response.request.options.merge(options)
                            sentCreds = true;
                            return retry(options);
                        }
                        return response
                    }];
                } else if (this.authType === "bearer") {
                    opts.headers.Authorization = `Bearer ${this.credentials.password || ""}`
                }
            }
            var payload = null;


            if (method !== 'GET' && method !== 'HEAD' && typeof msg.payload !== "undefined") {
                if (opts.headers['content-type'] == 'multipart/form-data' && typeof msg.payload === "object") {
                    let formData = new FormData();
                    for (var opt in msg.payload) {
                        if (msg.payload.hasOwnProperty(opt)) {
                            var val = msg.payload[opt];
                            if (val !== undefined && val !== null) {
                                if (typeof val === 'string' || Buffer.isBuffer(val)) {
                                    formData.append(opt, val);
                                } else if (typeof val === 'object' && val.hasOwnProperty('value')) {
                                    formData.append(opt, val.value, val.options || {});
                                } else {
                                    formData.append(opt, JSON.stringify(val));
                                }
                            }
                        }
                    }
                    // GOT will only set the content-type header with the correct boundary
                    // if the header isn't set. So we delete it here, for GOT to reset it.
                    delete opts.headers['content-type'];
                    opts.body = formData;
                } else {
                    if (typeof msg.payload === "string" || Buffer.isBuffer(msg.payload)) {
                        payload = msg.payload;
                    } else if (typeof msg.payload == "number") {
                        payload = msg.payload + "";
                    } else {
                        if (opts.headers['content-type'] == 'application/x-www-form-urlencoded') {
                            payload = querystring.stringify(msg.payload);
                        } else {
                            payload = JSON.stringify(msg.payload);
                            if (opts.headers['content-type'] == null) {
                                opts.headers[ctSet] = "application/json";
                            }
                        }
                    }
                    if (opts.headers['content-length'] == null) {
                        if (Buffer.isBuffer(payload)) {
                            opts.headers[clSet] = payload.length;
                        } else {
                            opts.headers[clSet] = Buffer.byteLength(payload);
                        }
                    }
                    opts.body = payload;
                }
            }


            if (method == 'GET' && typeof msg.payload !== "undefined" && paytoqs) {
                if (typeof msg.payload === "object") {
                    try {
                        if (url.indexOf("?") !== -1) {
                            url += (url.endsWith("?") ? "" : "&") + querystring.stringify(msg.payload);
                        } else {
                            url += "?" + querystring.stringify(msg.payload);
                        }
                    } catch (err) {

                        node.error(RED._("httpin.errors.invalid-payload"), msg);
                        nodeDone();
                        return;
                    }
                } else {

                    node.error(RED._("httpin.errors.invalid-payload"), msg);
                    nodeDone();
                    return;
                }
            } else if (method == "GET" && typeof msg.payload !== "undefined" && paytobody) {
                opts.allowGetBody = true;
                if (typeof msg.payload === "object") {
                    opts.body = JSON.stringify(msg.payload);
                } else if (typeof msg.payload == "number") {
                    opts.body = msg.payload + "";
                } else if (typeof msg.payload === "string" || Buffer.isBuffer(msg.payload)) {
                    opts.body = msg.payload;
                }
            }

            // revert to user supplied Capitalisation if needed.
            if (opts.headers.hasOwnProperty('content-type') && (ctSet !== 'content-type')) {
                opts.headers[ctSet] = opts.headers['content-type'];
                delete opts.headers['content-type'];
            }
            if (opts.headers.hasOwnProperty('content-length') && (clSet !== 'content-length')) {
                opts.headers[clSet] = opts.headers['content-length'];
                delete opts.headers['content-length'];
            }

            if (proxyUrl) {
                const match = proxyUrl.match(/^(https?:\/\/)?(.+)?:([0-9]+)?/i);
                if (match) {
                    const proxyURL = parseUrl(proxyUrl)
                    //set username/password to null to stop empty creds header
                    /** @type {import('hpagent').HttpProxyAgentOptions} */
                    let proxyOptions = {
                        proxy: proxyUrl,
                        scheduling: 'lifo',
                        maxFreeSockets: 256,
                        maxSockets: 256,
                        keepAlive: true
                    }
                    if (proxyConfig && proxyConfig.credentials) {
                        const proxyUsername = proxyConfig.credentials.username || '';
                        const proxyPassword = proxyConfig.credentials.password || '';
                        if (proxyUsername || proxyPassword) {
                            proxyOptions.proxy = proxyURL
                            proxyOptions.proxy.username = proxyUsername;
                            proxyOptions.proxy.password = proxyPassword;
                        }
                    } else if (proxyURL.username || proxyURL.password) {
                        proxyOptions.proxy = proxyURL
                        // proxyOptions.proxy.username = proxyURL.username;
                        // proxyOptions.proxy.password = proxyURL.password;
                    }
                    //need both incase of http -> https redirect
                    opts.agent = {
                        http: new HttpProxyAgent(proxyOptions),
                        https: new HttpsProxyAgent(proxyOptions)
                    };

                } else {
                    node.warn("Bad proxy url: " + proxyUrl);
                }
            }
            if (useKeepAlive && !opts.agent) {
                opts.agent = agents
            }
            if (tlsNode) {
                opts.https = {};
                tlsNode.addTLSOptions(opts.https);
                if (opts.https.ca) {
                    opts.https.certificateAuthority = opts.https.ca;
                    delete opts.https.ca;
                }
                if (opts.https.cert) {
                    opts.https.certificate = opts.https.cert;
                    delete opts.https.cert;
                }
            } else {
                if (msg.hasOwnProperty('rejectUnauthorized')) {
                    opts.https = { rejectUnauthorized: msg.rejectUnauthorized };
                }
            }

            // Now we have established all of our own headers, take a snapshot
            // of their case so we can restore it prior to the request being sent.
            if (opts.headers) {
                Object.keys(opts.headers).forEach(h => {
                    originalHeaderMap[h.toLowerCase()] = h
                })
            }

            // Allow custom options from the message object
            if (msg.request && msg.request.options && typeof (msg.request.options) === "object") {
                if (!opts.https) opts.https = {};
                if (msg.request.options.cert && msg.request.options.key) {
                    opts.https.key = msg.request.options.key;
                    opts.https.certificate = msg.request.options.cert;
                    opts.https.rejectUnauthorized = msg.request.options.rejectUnauthorized;
                } else if (msg.request.options.pfx && msg.request.options.passphrase) {
                    opts.https.pfx = msg.request.options.pfx;
                    opts.https.passphrase = msg.request.options.passphrase;
                    opts.https.rejectUnauthorized = msg.request.options.rejectUnauthorized;
                }
            }

            opts.url = url;
            try {
                const res = await got(opts);
                msg.statusCode = res.statusCode;
                msg.headers = res.headers;
                msg.responseUrl = res.url;

                if (jschardet.detect(res.body).encoding == "ascii") {
                    msg.payload = decodeAsciiString(res.body)
                }else{
                    msg.payload = res.body;
                }

                msg.redirectList = redirectList;
                msg.retry = 0;

                if (msg.headers.hasOwnProperty('set-cookie')) {
                    msg.responseCookies = extractCookies(msg.headers['set-cookie']);
                }
                msg.headers['x-node-red-request-node'] = hashSum(msg.headers);
                if (node.metric()) {
                    // Calculate request time
                    var diff = process.hrtime(preRequestTimestamp);
                    var ms = diff[0] * 1e3 + diff[1] * 1e-6;
                    var metricRequestDurationMillis = ms.toFixed(3);
                    node.metric("duration.millis", msg, metricRequestDurationMillis);
                    if (res.client && res.client.bytesRead) {
                        node.metric("size.bytes", msg, res.client.bytesRead);
                    }
                    if (timingLog) {
                        emitTimingMetricLog(res.timings, msg);
                    }
                }

                // Convert the payload to the required return type
                if (node.ret !== "bin") {
                    msg.payload = msg.payload.toString('utf8'); // txt
                    if (node.ret === "obj") {
                        try {
                            msg.payload = JSON.parse(msg.payload);
                        } catch (e) {
                            node.warn(RED._("httpin.errors.json-error"));
                        }
                    }
                }
                node.status({});
                node.send(msg);
                nodeDone();

            } catch (err) {
                if (err.code === 'ETIMEDOUT' || err.code === 'ESOCKETTIMEDOUT') {
                    node.error(RED._("common.notification.errors.no-response"), msg);
                    node.status({ fill: "red", shape: "ring", text: "common.notification.errors.no-response" });
                } else {
                    node.error(err, msg);
                    node.status({ fill: "red", shape: "ring", text: err.code });
                }
                msg.payload = err.toString() + " : " + url;
                msg.statusCode = err.code || (err.response ? err.response.statusCode : undefined);
                if (node.metric() && timingLog) {
                    emitTimingMetricLog(err.timings, msg);
                }
                if (!sendErrorsToCatch) {
                    nodeSend(msg);
                }
                nodeDone();
            };

        });

        this.on("close", function () {
            node.status({});
        });

        function emitTimingMetricLog(timings, msg) {
            const props = [
                "start",
                "socket",
                "lookup",
                "connect",
                "secureConnect",
                "upload",
                "response",
                "end",
                "error",
                "abort"
            ];
            if (timings) {
                props.forEach(p => {
                    if (timings[p]) {
                        node.metric(`timings.${p}`, msg, timings[p]);
                    }
                });
            }
        }

        /**
         * extract Cookies from array
         * @param {setCookie} setCookie - Array of cookie headers 
         * @returns {object} - Object of cookies
         */
        function extractCookies(setCookie) {
            var cookies = {};
            setCookie.forEach(function (c) {
                var parsedCookie = cookie.parse(c);
                var eq_idx = c.indexOf('=');
                var key = c.substr(0, eq_idx).trim()
                parsedCookie.value = parsedCookie[key];
                delete parsedCookie[key];
                cookies[key] = parsedCookie;
            });
            return cookies;
        }
    }

    RED.nodes.registerType("www-request-dynamic-tls", HTTPRequest, {
        credentials: {
            user: { type: "text" },
            password: { type: "password" }
        }
    });

    const md5 = (value) => { return crypto.createHash('md5').update(value).digest('hex') }
    const sha256 = (value) => { return crypto.createHash('sha256').update(value).digest('hex') }
    const sha512 = (value) => { return crypto.createHash('sha512').update(value).digest('hex') }

    function digestCompute(algorithm, value) {
        var lowercaseAlgorithm = ""
        if (algorithm) {
            lowercaseAlgorithm = algorithm.toLowerCase().replace(/-sess$/, '')
        }

        if (lowercaseAlgorithm === "sha-256") {
            return sha256(value)
        } else if (lowercaseAlgorithm === "sha-512-256") {
            var hash = sha512(value)
            return hash.slice(0, 64) // Only use the first 256 bits
        } else {
            return md5(value)
        }
    }

    function ha1Compute(algorithm, user, realm, pass, nonce, cnonce) {
        /**
        * RFC 2617: handle both standard and -sess algorithms.
        *
        * If the algorithm directive's value ends with "-sess", then HA1 is
        *   HA1=digestCompute(digestCompute(username:realm:password):nonce:cnonce)
        *
        * If the algorithm directive's value does not end with "-sess", then HA1 is
        *   HA1=digestCompute(username:realm:password)
        */
        var ha1 = digestCompute(algorithm, user + ':' + realm + ':' + pass)
        if (algorithm && /-sess$/i.test(algorithm)) {
            return digestCompute(algorithm, ha1 + ':' + nonce + ':' + cnonce)
        } else {
            return ha1
        }
    }

    function buildDigestHeader(user, pass, method, path, authHeader) {
        var challenge = {}
        var re = /([a-z0-9_-]+)=(?:"([^"]+)"|([a-z0-9_-]+))/gi
        for (; ;) {
            var match = re.exec(authHeader)
            if (!match) {
                break
            }
            challenge[match[1]] = match[2] || match[3]
        }
        var qop = /(^|,)\s*auth\s*($|,)/.test(challenge.qop) && 'auth'
        var nc = qop && '00000001'
        var cnonce = qop && uuid().replace(/-/g, '')
        var ha1 = ha1Compute(challenge.algorithm, user, challenge.realm, pass, challenge.nonce, cnonce)
        var ha2 = digestCompute(challenge.algorithm, method + ':' + path)
        var digestResponse = qop
            ? digestCompute(challenge.algorithm, ha1 + ':' + challenge.nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2)
            : digestCompute(challenge.algorithm, ha1 + ':' + challenge.nonce + ':' + ha2)
        var authValues = {
            username: user,
            realm: challenge.realm,
            nonce: challenge.nonce,
            uri: path,
            qop: qop,
            response: digestResponse,
            nc: nc,
            cnonce: cnonce,
            algorithm: challenge.algorithm,
            opaque: challenge.opaque
        }

        authHeader = []
        for (var k in authValues) {
            if (authValues[k]) {
                if (k === 'qop' || k === 'nc' || k === 'algorithm') {
                    authHeader.push(k + '=' + authValues[k])
                } else {
                    authHeader.push(k + '="' + authValues[k] + '"')
                }
            }
        }
        authHeader = 'Digest ' + authHeader.join(', ')
        return authHeader
    }

    /**
     *  Decode a string of ASCII codes into a string
     * @param {asciiInput} asciiInput to decode
     * @returns {string} decoded string
     */
    function decodeAsciiString(asciiInput) {
        const asciiString = String(asciiInput);
        let decodedString = '';
        let i = 0;

        while (i < asciiString.length) {
            let asciiCode;

            // Try to read 3 characters
            if (i + 2 < asciiString.length) {
                asciiCode = asciiString.substring(i, i + 3);
                if (parseInt(asciiCode, 10) < 128) {
                    decodedString += String.fromCharCode(parseInt(asciiCode, 10));
                    i += 3; // Move by 3 characters
                    continue;
                }
            }

            // Try to read 2 characters
            if (i + 1 < asciiString.length) {
                asciiCode = asciiString.substring(i, i + 2);
                if (parseInt(asciiCode, 10) < 128) {
                    decodedString += String.fromCharCode(parseInt(asciiCode, 10));
                    i += 2; // Move by 2 characters
                    continue;
                }
            }

            // If neither worked, move by 1 character to skip invalid input
            i += 1;
        }

        return decodedString;
    }
}