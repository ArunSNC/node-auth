const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { SECRET } = require('../config/index')

/**
 * @description to register the user (ADMIN , SUPERADMIN, USER)
 * @param {*} userDets User details
 * @param {*} role User role
 * @param {*} res response
 */
const userRegister = async (userDets, role, res) =>{

    try {

        // Validate Username
    let usernameNotTaken = await validateUsername(userDets.username);
    if(!usernameNotTaken){
        return res.status(400).json({
            message: 'username already taken',
            timestamp: Date.now(),
            success: false
        });
    }

    //Validate Email
    let emailNotRegistered = await validateEmail(userDets.email)
    if(!emailNotRegistered){
        return res.status(400).json({
            message: 'email already registered',
            timestamp: Date.now(),
            success: false
        });
    }

    // After above validations create hashed password
    let salt = await bcrypt.genSalt(12);
    let hashedPassword = await bcrypt.hash(userDets.password, salt);

    // Create new user
    const newUser = new User({
        ... userDets,
        password: hashedPassword,
        role: role
    });

    await newUser.save();
    return res.status(201).json({
        message: 'user successfully registered, please try to login..!',
        success: true
    });

    } catch (err) {
        return res.status(500).json({
            message: 'Unable to register user',
            success: false
        });
    }
}


/**
 * @description to Login the user (ADMIN , SUPERADMIN, USER)
 * @param {*} userCreds User details
 * @param {*} role User role
 * @param {*} res response
 */
const userLogin = async (userCreds, role, res) =>{
    let { username, password } = userCreds;
    let user = await User.findOne({username});
    if(!user) return res.status(404).json({
        message: 'Username not found, invalid login credentials',
        success: false
    });

    if(user.role !== role) return res.status(403).json({
        message: 'Please login from right portal',
        success: false
    });

    if(await bcrypt.compare(password, user.password)){

        let token = jwt.sign({
            user_id: user._id,
            username: user.username,
            role: user.role,
            email: user.email,
        }, SECRET ,{ expiresIn: '7 days' });

        let result = {
            username: user.username,
            role: user.role,
            email: user.email,
            token: `Bearer ${token}`,
            expiresIn: 168
        }

        return res.status(200).json({

            ... result,
            message: 'Successfully logged in..',
            success: true
        });

    }else{
        return res.status(403).json({
            message: 'Incorrect password, try logging in again',
            success: false
        });
    }
}


// Validate Username in database
const validateUsername = async (username) =>{
    let user = await User.findOne({ username });
    return user ? false : true;
}


// Validate Email in Database
const validateEmail = async (email) =>{
    let user = await User.findOne({ email });
    return user ? false : true;
}

/**
 * @description Passport Middleware
 */
const userAuth = passport.authenticate("jwt",{ session: false });


/**
 * @description Serialize User
 */
const serializeUser = (user) =>{
    return {
        username: user.username,
        email: user.email,
        name: user.name,
        id: user._id,
        updatedAt: user.updatedAt,
        createdAt: user.createdAt
    }
}


/**
 * @description Check Role Middleware
 */
const checkRole = (roles) => (req, res, next)=>
    !roles.includes(req.user.role) ? res.status(401).json("Unaothorized") : next()

module.exports = {
    userRegister,
    userLogin,
    userAuth,
    serializeUser,
    checkRole
}