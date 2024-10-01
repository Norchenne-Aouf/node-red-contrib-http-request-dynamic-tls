
# node-red-contrib-http-request-dynamic-tls
This is a Node-RED node for performing HTTP(S) requests using the [Request](https://github.com/request/request) library with optimized proxy and SSL/TLS support. This node is forked from `node-red-contrib-http-request` to add **multipart request** functionality and resolve **SSL/TLS issues**.

## Installation
To install, run:

```bash
npm install -g node-red-contrib-http-request-dynamic-tls
```

[![npm package](https://nodei.co/npm/node-red-contrib-http-request-dynamic-tls.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/node-red-contrib-http-request-dynamic-tls/)

## Features
This module builds upon the Node-RED core HTTP/HTTPS request node and the versatile [Request](https://github.com/request/request) library, which includes features for proxying, streaming, and comprehensive TLS/SSL support.

### Key Enhancements in This Fork:
- **Multipart Request Support**: Added support for sending multipart form data in HTTP requests, a feature that the original node lacked.
- **Improved SSL/TLS Handling**: Resolved issues related to SSL/TLS configuration, ensuring compatibility with secure HTTPS endpoints and proxies.
- **Optimized Proxy Support**: Supports HTTP over HTTPS proxies using the CONNECT method, which is not possible with the Core Node-RED HTTP Request node.

## Node Configuration and Usage

This node allows you to make HTTP(S) requests, with options that can either be configured directly in the node or passed dynamically using incoming messages (`msg` object).

### Available Options:

1. **URL**:
   - Can be configured in the node or set dynamically using `msg.url`.
   - Must start with `http:` or `https:`.
   - You can use [mustache-style](http://mustache.github.io/mustache.5.html) tags in the URL to insert dynamic values from the incoming message, e.g., `example.com/{{{topic}}}` will use the value of `msg.topic`.

2. **HTTP Method**:
   - Configurable in the node or via `msg.method`.
   - Supported methods: `GET`, `PUT`, `POST`, `PATCH`, `DELETE` (default is `GET`).

3. **Headers**:
   - Use `msg.headers` to add custom HTTP headers to the request. This should be an object containing field/value pairs.

4. **Request Body**:
   - The `msg.payload` will be sent as the body of the request. For multipart form-data, ensure that the payload is structured correctly.

5. **SSL/TLS Options**:
   - SSL/TLS certificates can be passed via `msg.request.options`, which includes options such as:
     - `cert`: The certificate for the request.
     - `key`: The private key for the request.
     - `pfx`: The pfx file for the request.
     - `passphrase`: The passphrase for the private key or pfx file.

### Output Message:
The output message (`msg`) will contain:
- **`payload`**: The body of the response.
- **`statusCode`**: The HTTP status code of the response, or the error code if the request failed.
- **`headers`**: An object containing the response headers.

### Proxy Configuration:
To configure a proxy, set the `http_proxy` environment variable before starting Node-RED:

```bash
export http_proxy=http://your.proxy.server:port
```

## Example Use Case
Need to upload a file through an HTTP POST request while using an HTTPS proxy? This module handles multipart form data and routes requests securely over a proxy, something the core Node-RED HTTP node cannot do.

## Contribution
By contributing to `node-red-contrib-http-request-dynamic-tls`, you’re helping to build a more robust and feature-rich HTTP client for the Node-RED ecosystem. Contributions, bug reports, and suggestions are welcome!
