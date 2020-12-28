const cors = require('cors');
const express = require('express');
const bp = require('body-parser');
const { connect } = require('mongoose');
const { success, error } = require('consola');
const passport = require('passport');

// Import configuration
const { DB,PORT } = require('./config/index');

// initialize application
const app = express();


// Middleware
app.use(cors());
app.use(bp.json({
    extensions: true
}));
app.use(passport.initialize());


require('./middlewares/passport')(passport);


// Router Middleware
app.use('/api/users', require('./routes/users'));



// Connect to DB
const startApp = async () =>{

    try {
         await connect(DB, {
            useFindAndModify: true,
            useUnifiedTopology: true,
            useNewUrlParser: true
        });

        success({
            message: `Successfully connected with the Database \n${DB}`,
            badge: true
        });

        app.listen(PORT,()=>{
            success({
                message: `Server started on PORT ${PORT}`,
                badge: true
            });
        });
    } catch (err) {
        error({
            message: `Unsucessful connecting with the Database\n${err}`,
            badge: true
        });
        startApp();
    }
}

startApp();