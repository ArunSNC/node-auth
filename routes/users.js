const router = require('express').Router();

// Call registeration function
const { userRegister, userLogin, userAuth, serializeUser, checkRole} = require('../utils/Auth');

// user registration route
router.post('/register-user', async (req, res) =>{
    await userRegister(req.body, 'user', res);
});

// admin registration route
router.post('/register-admin', async (req, res) =>{
    await userRegister(req.body, 'admin', res);
});

// superadmin registration route
router.post('/register-super-admin', async (req, res) =>{
    await userRegister(req.body, 'superadmin', res);
});


// user login route
router.post('/login-user', async (req, res) =>{
    await userLogin(req.body, 'user', res);
});

// admin login route
router.post('/login-admin', async (req, res) =>{
    await userLogin(req.body, 'admin', res);
});

// superadmin login route
router.post('/login-super-admin', async (req, res) =>{
    await userLogin(req.body, 'superadmin', res);
});


// profile route
router.get('/profile', userAuth, async (req, res) =>{
    res.json(serializeUser(req.user));
});

// user protected route
router.get('/user-protected', userAuth, checkRole(['user']), async (req, res) =>{
    res.send('Hello user');
});

// admin protected route
router.get('/admin-protected', userAuth, checkRole(['admin']), async (req, res) =>{
    res.send('Hello admin');

});

// superadmin protected route
router.get('/super-admin-protected', userAuth, checkRole(['superadmin']), async (req, res) =>{
    res.send('Hello super-admin');

});


router.get('/admin-and-superadmin-protected', userAuth, checkRole(['admin','superadmin']),async (req, res)=>{
    res.send('Hello admin and superadmin');
})


router.get('/universal-access', userAuth, checkRole(['user','admin','superadmin']), async (req, res) =>{
    res.send('Hello world');
})

module.exports = router;