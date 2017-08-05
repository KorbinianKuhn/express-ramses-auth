const express = require('express');
const bodyParser = require('body-parser');
const ramses = require('../');
const keys = require('./keys/keys')
const app = express();
const request = require('request');

var invalidTickets = [];

const isRevokedFunction = function (ticket) {
  for (let i = 0; i < invalidTickets.length; i++) {
    if (invalidTickets[i] === ticket.payload.jti) {
      return true;
    }
  }
  return false;
}

const isAuthorized = function (authorizedParty, audience) {
  if (authorizedParty === 'User' && audience === 'Service-A') {
    return true;
  } else if (authorizedParty === 'Service-A' && audience === 'Service-B') {
    return true;
  } else {
    return false;
  }
}

app.use(bodyParser.urlencoded({
  extended: true
}));

//Auth Service
app.use('/auth/logout', ramses.middleware({
  key: keys.publicKeyAuth,
  isRevokedFunction: isRevokedFunction
}));

app.post('/auth/login', function (req, res) {
  if (req.body.username === "ramses" && req.body.password === "secret") {
    const ticket = ramses.sign({
        user: req.body.username,
        iss: 'Auth-Service',
        aud: 'Ticket-Service',
        azp: 'User'
      },
      keys.privateKeyAuth, {
        lifetime: 3600,
        jti: true
      }
    )
    res.status(200).send(ticket);
  } else {
    res.status(400).send('Login failed.');
  }
});

app.post('/logout', function (req, res) {
  invalidTickets.push(req.user.payload.jti);
  res.send('Logout');
});

//Ticket-Service
app.use('/ticket', ramses.middleware({
  key: function (ticket) {
    if (ticket.payload.iss === 'Auth-Service') {
      return keys.publicKeyAuth;
    } else {
      return keys.publicKeyTicket;
    }
  },
  isRevokedFunction: isRevokedFunction
}));

app.post('/ticket', function (req, res) {
  if (req.body.audience) {
    if (req.body.azp && req.body.proof) {
      var azp = req.body.azp;
      if (azp === 'Service-A') {
        if (!ramses.verifyProof(req.headers.authorization, req.body.proof, keys.publicKeyServiceA)) {
          return res.status(401).send(`Invalid proof. Sign the jwt id with the correct private key.`);
        }
      } else {
        return res.status(401).send(`Interservice ticket requests are not possible for [${azp}]`);
      }
    } else {
      var azp = req.user.payload.azp;
    }
    if (!isAuthorized(azp, req.body.audience)) {
      res.status(401).send(`${req.user.payload.azp} is not authorized to access ${req.body.audience}`)
    } else {
      const ticket = ramses.sign({
          user: req.body.username,
          iss: 'Ticket-Service',
          aud: req.body.audience,
          azp: azp
        },
        keys.privateKeyTicket, {
          lifetime: 3600,
          jti: true
        }
      )
      res.status(200).send(ticket);
    }
  } else {
    res.status(400).send('Missing body parameter [audience].');
  }
});

//Service-A
app.use('/service-a', ramses.middleware({
  key: keys.publicKeyTicket,
  aud: 'Service-A',
  isRevokedFunction: isRevokedFunction
}));

app.get('/service-a', function (req, res) {
  res.status(200).send("Success");
});

app.get('/service-a/interservice', function (req, res) {
  request.post('http://localhost:3000/ticket', {
    form: {
      audience: 'Service-B',
      azp: 'Service-A',
      proof: ramses.createProof(req.headers.authorization, keys.privateKeyServiceA)
    },
    headers: {
      'Authorization': req.headers.authorization
    }
  }, function (err, response, body) {
    if (err) {
      res.status(401).send(err);
    }
    if (response.statusCode !== 200) {
      res.status(400).send(body);
    } else {
      console.log(ramses.decode(body));
      res.status(200).send(`Success. This is the ticket for Service-B: [${body}]`);
    }
  })
});

//Service-B
app.use('/service-B', ramses.middleware({
  key: keys.publicKeyTicket,
  aud: 'Service-B',
  isRevokedFunction: isRevokedFunction
}));

app.get('/service-b', function (req, res) {
  res.status(200).send("Success");
});

app.listen(3000, function () {
  console.log('Services are listening on port 3000 [/auth, /ticket, /service-a, /service-b] !');
});
