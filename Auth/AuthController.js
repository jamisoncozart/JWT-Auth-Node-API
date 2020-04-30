const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
const User = require('../user/User');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config/config');
const VerifyToken = require('./VerifyToken');

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

// logout route isn't necessary because you can destroy the JWT on the front-end
// USER LOGOUT - NULLIFY JWT
router.get('/logout', function(req, res) {
  res.status(200).send({ auth: false, token: null });
})

// USER GET INFO - SEND USER INFO TO AUTHORIZED USER
router.get('/me', VerifyToken, function(req, res, next) {
  User.findById(req.userId, { password: 0 }, function(err, user) {
    if(err) return res.status(500).send("There was a problem finding the user.");
    if(!user) return res.status(404).send("No user found.");
    
    res.status(200).send(user);  
  });
});

module.exports = router;