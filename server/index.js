require('dotenv').config();
const express = require('express');
const session = require('express-session');
const massive = require('massive');
const authCtrl = require('./controllers/authController')
const treasureCtrl = require('./controllers/treasureController')
const auth = require('./middleware/authMiddleware')

const { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env 

const app = express()
app.use(express.json())

massive( CONNECTION_STRING ).then( db => {
    app.set( 'db', db )
    console.log('db connected');
})

app.use(session({
    secret: SESSION_SECRET,
    resave: true,
    saveUninitialized: false
}))

// AUTH ENDPOINTS
app.post("/auth/register", authCtrl.register)
app.post("/auth/login", authCtrl.login)
app.get("/auth/logout", authCtrl.logout)

// TREASURE ENDPOINTS
app.get("/api/treasure/dragon", treasureCtrl.dragonTreasure)
app.get("/api/treasure/user", auth.usersOnly, treasureCtrl.getUserTreasure)
app.post("/api/treasure/user", auth.usersOnly, treasureCtrl.addUserTreasure)
app.get("/api/treasure/all", auth.usersOnly, auth.adminsOnly, treasureCtrl.getAllTreasure)

app.listen(SERVER_PORT, () => {
    console.log(`Set on PORT ${SERVER_PORT}`);
})