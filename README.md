# express-ramses-auth [![Travis](https://img.shields.io/travis/KorbinianKuhn/express-ramses-auth.svg)](https://travis-ci.org/KorbinianKuhn/ramses-auth/builds)  [![standard](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](http://standardjs.com/)

#### Implementation of RAMSES - Robust Access Model for Securing Exposed Services

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
$ npm install --save ramses-auth
```

or clone the repository:
```
$ git clone https://github.com/KorbinianKuhn/ramses-auth
```

## Usage


## Testing

First you have to install all dependencies:

```
$ npm install
```

To execute all unit tests once, use:

```
$ npm test
```

or to run tests based on file watcher, use:

```
$ npm start
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