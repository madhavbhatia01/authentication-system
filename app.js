//jshint esversion:6
require('dotenv').config()
const express = require("express");
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.urlencoded({
  extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = {
  email : {type : String, required : true, unique : true},
  username : {type : String, required : true, unique : true},
  password : {type : String, required : true}
};

const User = mongoose.model("User", userSchema);

//function to check wether email address is valid
function validateEmail(email) {
  var atPos = email.indexOf("@");
  var dotPos = email.lastIndexOf(".");
  return atPos > 0 && dotPos > atPos + 1 && dotPos < email.length - 1;
}

//function to check wether password is Incorrect
async function isPasswordValid(password, hashedPassword){
  return await bcrypt.compare(password, hashedPassword);
}

const invalidTokens = [];

//funtion to validate token
const validateToken = (req, res, next)=>{
  var token = req.header('Authorization');
  if(!token){
    return res.status(401).send("No token found for Authorization !");
  }
  token = token.substr(7); //remove Bearer from start
  if(invalidTokens.includes(token)){
    return res.status(401).send("Invalid token !");
  }

  try{
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.userId = decoded.userId;
    req.token = token;
    next();
  }catch(error){
    res.status(401).send("Invalid token !");
  }
}

// POST /register
app.post('/register', async(req, res)=>{
  try{
    const {email, username, password} = req.body;

    if(!validateEmail(email)){
      return res.status(400).send("Invalid email address");
    }

    const existingUsername = await User.findOne({username});
    if(existingUsername){
      return res.status(400).send("This username already exists !");
    }

    const existingEmail = await User.findOne({email});
    if(existingEmail){
      return res.status(400).send("This email is already taken !");
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      username,
      password : hashPassword
    });
    await user.save();

    res.status(200).send("Successfully registered !");

  }catch(error){
    res.status(500).send("Following error occured :\n" + error);
  }
});

// POST /login
app.post('/login', async(req, res)=>{
  try{
    const {username, password} = req.body;

    const user = await User.findOne({username});
    if(!user){
      return res.status(401).send("Invalid Username !");
    }

    const checkPassword = await isPasswordValid(password, user.password);
    if(!checkPassword){
      return res.status(401).send("Incorrect Password !");
    }

    const token = jwt.sign({userId: user._id}, process.env.SECRET_KEY);
    res.status(200).send("Successfully logged in, token : " + token);
  }catch(error){
    res.status(500).send("Following error occured :\n" + error);
  }
});

// POST /logout
app.post('/logout', validateToken, async(req, res)=>{
  try{
    const userId = req.userId;
    const user = await User.findById(userId);
    if(!user){
      return res.status(400).json("No user exists !");
    }

    invalidTokens.push(req.token);
    res.status(200).send("Logged out successfully !");
  }catch(error){
    res.status(500).send("Following error occured :\n" + error);
  }
});

// GET /profile
app.get('/profile', validateToken, async(req, res)=>{
  try{
    const userId = req.userId;
    const user = await User.findById(userId);
    if(!user){
      return res.status(400).json("No user exists !");
    }
    res.status(200).send(user);
  }catch(error){
    res.status(500).send("Following error occured :\n" + error);
  }
});

// PUT /profile
app.put('/profile', validateToken, async(req, res)=>{
  try {
    const userId = req.userId;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(401).send('User not found !');
    }

    if(req.body.password){
      const hashPassword = await bcrypt.hash(req.body.password, 10);
      user.password = hashPassword;
    }

    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    await user.save();

    res.status(200).send(user);
  } catch (error) {
    res.status(500).send("Following error occured :\n" + error);
  }
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
