const express = require('express');
const router = express.Router();

const bcrypt = require("bcryptjs");
const saltRounds = 10;

const User = require("../models/User.model");

const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");

router.get("/signin", isLoggedOut, (req, res, next) => {
  //renderizar formulario de signin
  res.render("users/signin");
});

router.post("/signin", isLoggedOut, (req, res, next) => {
  
  //recupero campos del formulario
  let {username, password, passwordRepeat} = req.body;
  
  //comprobaciones de campos
  if(username == "" || password == "" || passwordRepeat == "") {
    res.render("users/signin", {mensajeError: "Faltan campos"});
    return;
  }
  else if(password != passwordRepeat) {
    res.render("users/signin", {mensajeError: "Passwords diferentes"});
    return;
  }
  
  User.find({username})
  .then(results => {
    console.log("results ", results);
    // if(results) {  //[{username: "Mariona", password: "1234"}]
    if(results.length != 0) {
      //error
      res.render("users/signin", {mensajeError: "El usuario ya existe"});
      return;
    }
    //el usuario ha pasado las validaciones

    //proceso de encriptación con bcrypt:
    let salt = bcrypt.genSaltSync(saltRounds);
    let passwordEncriptado = bcrypt.hashSync(password, salt);

    User.create({
      username: username, 
      password: passwordEncriptado
    })
    .then(result => {
      res.redirect("/user/login");
    })
    .catch(err => next(err))
  })
  .catch(err => {
    console.log("err ", err);
    next(err);
  })
  
})

router.get("/login", isLoggedOut, (req, res, next)=> {
  console.log("REQ.SESSION: ", req.session);
  res.render("users/login");
})
router.post("/login", isLoggedOut, (req, res, next)=>{
  
  let {username, password} = req.body;
  //username = "Mariona"
  //password = "1234"

  if(username == "" || password == "") {
    res.render("users/login", { mensajeError: "Faltan campos" });
    return;
  } 

  User.find({username})
  .then(results => {
    if(results.length == 0) {
      res.render("users/login", { mensajeError: "Credenciales incorrectas" });
      return;
    }
    // else if(results[0].password != password) {
    //   res.render("users/login", { mensajeError: "Credenciales incorrectas" });
    //   return;
    // }
    //results[0] = { username: "Mariona", password = "12312423452465356477356253414324313524524"}

    if(bcrypt.compareSync(password, results[0].password)) {
      req.session.currentUser = username; //en req.session.currentUser guardamos la información del usuario que nos interese. Podemos guardar un string o un objeto con todos los datos
      res.redirect("/user/profile");
    } else {
      res.render("users/login", { mensajeError: "Credenciales incorrectas" });
    }
  })
  .catch(err => next(err));

})

router.get("/profile", isLoggedIn, (req, res, next) => {
  res.render("users/profile", {username: req.session.currentUser});
})

router.get("/logout", isLoggedIn, (req, res, next)=>{
  req.session.destroy(err => {
    if(err) next(err);
    else res.redirect("/user/login");
  });
});

module.exports = router;
