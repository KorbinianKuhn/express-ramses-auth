# express-ramses-auth [![Travis](https://img.shields.io/travis/KorbinianKuhn/express-ramses-auth.svg)](https://travis-ci.org/KorbinianKuhn/ramses-auth/builds)  [![standard](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](http://standardjs.com/)

#### Express implementation of RAMSES - Robust Access Model for Securing Exposed Services

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Testing](#testing)
5. [Contribution](#contribution)
6. [License](#license)

## Introduction

RAMSES is an easily adoptable, customizable and
robust security model which will not consider any trusted
zones. It proposes an authentication and authorization pattern
for inter-service communication utilizing and extending JSON
Web Signatures (JWS) as tickets. RAMSES includes various
extensions for individual security levels and requirements, like
access capabilities, ticket invalidation, usage limitation and
payload encryption.

A detailed explanation of RAMSES will follow.

This library copied a lot of code from this awesome library [express-jwt](https://github.com/auth0/express-jwt).

## Installation

For installation use the [Node Package Manager](https://github.com/npm/npm):

```
$ npm install --save express-ramses-auth
```

or clone the repository:
```
$ git clone https://github.com/KorbinianKuhn/express-ramses-auth
```

## Usage

The RAMSES authentication middleware authenticates callers using a JWT.
If the token is valid, `req.user` will be set with the decoded JSON object to be used by later middleware for authorization and access control.

For example,

```javascript
const ramses = require('express-ramses-auth');
const publicKey = fs.readFileSync('/path/to/public.pub');

app.get('/protected',
  ramses({key: publicKey}),
  function(req, res) {
    if (!req.user) return res.sendStatus(401);
    res.sendStatus(200);
  });
```

By default, the decoded tokens payload is attached to `req.user` but can be configured with the `requestProperty` option.

```javascript
ramses({ key: publicKey, requestProperty: 'auth' });
```

The token can also be attached to the `result` object with the `resultProperty` option.

```javascript
ramses({ key: publicKey, resultProperty: 'locals.user' });
```

The full decoded token (header, payload and signature) can be attached with the `attachFullToken` option.

```javascript
ramses({ key: publicKey, attachFullToken: true });
```

Both `resultProperty` and `requestProperty` utilize [lodash.set](https://lodash.com/docs/4.17.2#set) and will accept nested property paths.

A custom function for extracting the token from a request can be specified with the `getToken` option. This is useful if you need to pass the token through a query parameter or a cookie. You can throw an error in this function and it will be handled by `express-ramses-auth`.

```javascript
app.use(ramses({
  key: publicKey,
  credentialsRequired: false,
  getToken: function fromHeaderOrQuerystring (req) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
      return req.query.token;
    }
    return null;
  }
}));
```

### Multi-tenancy

If you are developing an application in which the key used to sign tokens is not static, you can provide a callback function as the `key` parameter. The function has the signature: `function(req, dtoken)`:

* `req` (`Object`) - The express `request` object.
* `dtoken` (`Object`) - An object with the decoded JWT header, payload and signature.
* `done` (`Function`) - A function with signature `function(err, key)` to be invoked when the key is retrieved.
  * `err` (`Any`) - The error that occurred.
  * `key` (`String`) - The key to use to verify the JWT.

For example, if the key varies based on the [JWT issuer](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#issDef):

```javascript
const ramses = require('express-ramses-auth');
const data = require('./data');
const utilities = require('./utilities');

const keyCallback = function(req, dtoken, done){
  const issuer = dtoken.payload.iss;

  data.getTenantByIdentifier(issuer, function(err, tenant){
    if (err) { return done(err); }
    if (!tenant) { return done(new Error('missing_key')); }

    const key = utilities.decrypt(tenant.key);
    done(null, key);
  });
};

app.get('/protected',
  ramses({key: keyCallback}),
  function(req, res) {
    if (!req.user) return res.sendStatus(401);
    res.sendStatus(200);
  });
```

Optionally you can make some paths unprotected as follows:

```javascript
app.use(ramses({ key: publicKey}).unless({path: ['/skip']}));
```

This is especially useful when applying to multiple routes. In the example above, `path` can be a string, a regexp, or an array of any of those.

> For more details on the `.unless` syntax including additional options, please see [express-unless](https://github.com/jfromaniello/express-unless).

### Revoked tokens

It is possible that some tokens will need to be revoked so they cannot be used any longer. You can provide a function as the `isRevoked` option. The signature of the function is `function(req, payload, done)`:

* `req` (`Object`) - The express `request` object.
* `dtoken` (`Object`) - An object with the decoded JWT header, payload and signature.
* `done` (`Function`) - A function with signature `function(err, revoked)` to be invoked once the check to see if the token is revoked or not is complete.
  * `err` (`Any`) - The error that occurred.
  * `revoked` (`Boolean`) - `true` if the JWT is revoked, `false` otherwise.

For example, if the `(iss, jti)` claim pair is used to identify a JWT:

```javascript
const ramses = require('express-ramses-auth');
const data = require('./data');
const utilities = require('./utilities');

const isRevokedCallback = function(req, dtoken, done){
  const issuer = dtoken.payload.iss;
  const tokenId = dtoken.payload.jti;

  data.getRevokedToken(issuer, tokenId, function(err, token){
    if (err) { return done(err); }
    return done(null, !!token);
  });
};

app.get('/protected',
  ramses({key: publicKey,
    isRevoked: isRevokedCallback}),
  function(req, res) {
    if (!req.user) return res.sendStatus(401);
    res.sendStatus(200);
  });
```

### Error handling

The default behavior is to throw an error when the token is invalid, so you can add your custom logic to manage unauthorized access as follows:

```javascript
app.use(function (err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    res.status(401).send('invalid token...');
  }
});
```

You might want to use this module to identify registered users while still providing access to unregistered users. You
can do this by using the option _credentialsRequired_:

```javascript
app.use(ramses({
  key: publicKey,
  credentialsRequired: false
}));
```

### Ticket validation

The middleware maps all options of the [ramses-auth](https://github.com/KorbinianKuhn/ramses-auth) package:

`aud` (String): Audience that must be part of the `aud` claim.
`azp` (String): Authorized party that must be part of the `azp` claim.

### RAMSES functions

The middleware exports all functions of the [ramses-auth](https://github.com/KorbinianKuhn/ramses-auth) package:

* `sign(payload, key, options, callback)`
* `verify(ticket, key, options, callback)`
* `decode(ticket, options)`

### Proof of possession

The middleware provides two functions to create and verify a proof of possession, that is necessary to create an AccessTicket from an AccessTicket. As RAMSES specifies, the `jti` claim must be part of the ticket.

```javascript
ramses.createProof(req, key, function(err, proof) {
  console.log(proof);
});

ramses.createProof(req, proof, key, function(err, valid) {
  console.log(valid);
});
```

## Testing

First you have to install all dependencies:

```
$ npm install
```

To execute all unit tests once, use:

```
$ npm test
```

To get information about the test coverage, use:

```
$ npm run coverage
```

## Contribution

Fork this repository and push in your ideas.

Do not forget to add corresponding tests to keep up 100% test coverage.

## License

The MIT License

Copyright (c) 2017 Korbinian Kuhn, Tobias Eberle, Christof Kost, Steffen Mauser, Marc Schelling

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.