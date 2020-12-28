const User = require('../models/User');
const { SECRET } = require('../config/index');
const { Strategy, ExtractJwt } = require('passport-jwt');
const passport = require('passport');

const opts ={
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: SECRET
}

module.exports = (passport) =>{
    passport.use(new Strategy(opts, async(payload, done) =>{
        await User.findById(payload.user_id).then(user =>{
           return user ? done(null, user) : done(null, false); // ternary
        }).catch(err =>{
            return done(null,false);
        })
    }))
}