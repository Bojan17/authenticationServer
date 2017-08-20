const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');
//create local Strategy
const localLogin = new LocalStrategy({usernameField: 'email'},function(email,password,done){
  User.findOne({email:email},function(err,user){
    if(err){return done(err)}
    if(!user){return done(null,false)}

    user.comparePassword(password,function(err, isMatch){
      if(err){return done(err)}
      if(isMatch){return done(null, false)}

      return done(null,user);
    })
  })
})
//setup options for jwt Strategy
const jwtOptions={
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};
//create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions,function(payload,done){
  //check if user ID in the payload exist in our database
  //if does call done wit that,otherwise call done without  a user object
  User.findById(payload.sub, function(){
    if(err){return done(err, false);}

    if(user){
      done(null,user);
    }else{
      done(null,false);
    }
  });

});

//tell passport to use this Strategy
passport.use(jwtLogin);
