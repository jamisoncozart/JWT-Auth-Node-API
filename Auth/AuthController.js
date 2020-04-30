const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
const User = require('../user/User');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config/config');

// USER REGISTER - GENERATE JWT
router.post('/register', function(req, res) {
  const hashedPassword = bcrypt.hashSync(req.body.password, 8);

  User.create({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword
  },
  function(err, user) {
    if(err) {
      return res.status(500).send("There was a problem registering the user.");
    } else {
      const token = jwt.sign({ id: user._id }, config.secret, {
        expiresIn: 86400 // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token });
    }
  });
});

// USER LOGIN - GENERATE JWT
router.post('/login', function(req, res) {
  User.findOne({ email: req.body.email }, function(err, user) {
    if(err) {
      return res.status(500).send('Internal Server error, please try again.');
    } else if(!user) {
      return res.status(404).send('There is no user with that email address.');
    } else {
      const passwordIsValid = bcrypt.compareSync(req.body.password, user.password); //verifies password
      if(!passwordIsValid) {
        return res.status(401).send({ auth: false, token: null });
      } else {
        const token = jwt.sign({ id: user._id }, config.secret, {
          expiresIn: 86400 // expires in 24 hours
        });
        res.status(200).send({ auth: true, token: token });
      }
    }
  });
});

// USER LOGOUT - NULLIFY JWT
router.get('/logout', function(req, res) {
  res.status(200).send({ auth: false, token: null });
})

// USER GET INFO - SEND USER INFO TO AUTHORIZED USER
router.get('/me', function(req, res) {
  const token = req.headers['x-access-token'];
  if(!token) {
    return res.status(401).send({ auth: false, message: 'No token provided' });
  } else {
    jwt.verify(token, config.secret, function(err, decoded) {
      if(err) {
        return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
      } else {
        User.findById(decoded.id, 
          { password: 0 }, //projection to query that omits the password
          function(err, user) {
          if(err) {
            return res.status(500).send("There was a problem finding the user.");
          } else if(!user) {
            return res.status(404).send("No user found.");
          } else {
            res.status(200).send(user);
          }
        });
      }
    });
  }
});

module.exports = router;