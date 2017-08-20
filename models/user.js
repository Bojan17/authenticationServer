const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

const userSchema = new Schema({
  email: {
    type: String,
    unique: true,
    lowercase: true
          },
  password: String
});

//crypting password before it's saved
userSchema.pre('save',function(next){
  const user = this;

//generate a salt and run callback after it has been created
  bcrypt.genSalt(10,function(err,salt){
    if(err){
      return next(err);
    }

//hash password using salt,after it's done send encrypted password
    bcrypt.hash(user.password, salt, null, function(err,hash){
      if(err){return next(err);}
      user.password = hash;
      next();
    });
  });
});
userSchema.methods.comparePassword = function(candidatePassword, callback){
    bcrypt.compare(candidatePassword, this.password,function(err, isMatch){
      if(err){return callback(err)}
      callback(null,isMatch);
    })
}

const modelClass = mongoose.model('user', userSchema);

module.exports = modelClass;
