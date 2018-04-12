const express = require('express'),
  fs = require('fs'),
  path = require('path'),
  xFrameOptions = require('x-frame-options'),
  bodyParser = require('body-parser'),
  cookieparser = require('cookie-parser'),
  session = require('express-session'),
  serveStatic = require('serve-static'),
  passport = require('passport'),
  multer = require('multer'),
  spdy = require('spdy'),
  RedisStore = require('connect-redis')(session);

// register passport dummy-stategy
require('./passport-local-plugin.js')(passport);

// setting the Port
const port = +(process.env.PORT || '3000');
// directories

const cwd = process.cwd(),
  htmlPublic = path.resolve(cwd, 'test', 'html');


const ensureLoggedIn = {
  isRequired: function(req, res, next) {
    // console.log('ensureLoggedIn isRequired', req.user, req.isAuthenticated() )
    if (!(req.isAuthenticated && req.isAuthenticated())) {
      res.sendStatus(401)
    } else {
      next()
    }
  },
  notRequired: function(req, res, next) {
    next()
  }
}


const app = express(),
  sessionSecret = String(Math.random().toString(16).slice(2)),
  sessionStore = new RedisStore(),
  sessionMiddleWare = session({
    store: sessionStore,
    key: 'connect.sid',
    secret: sessionSecret,
    resave: true,
    rolling: true,
    saveUninitialized: false,
    cookie: {
      secure: true,
      maxAge: 7 * 24 * 3600 * 1000
    }
  })

// SSL settings
const sslSettings = {};
const passphrase = JSON.parse(fs.readFileSync(path.resolve(cwd, 'test', 'credentials/ca.pw.json'), 'utf8'));

sslSettings.key = fs.readFileSync(path.resolve(cwd, 'test', 'credentials/ca.key'), 'utf8');
sslSettings.cert = fs.readFileSync(path.resolve(cwd, 'test', 'credentials/ca.crt'), 'utf8');
sslSettings.passphrase = passphrase.password || passphrase;
sslSettings.rejectUnauthorized = false
sslSettings.requestCert = true
sslSettings.agent = false

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());
const cookieParser = cookieparser(sessionSecret);
app.use(cookieParser);
app.use(sessionMiddleWare)

// Prevent Clickjacking
// app.use(xFrameOptions())

// register for authentification
app.use(passport.initialize())
// init session handler
app.use(passport.session())

passport.serializeUser( (user, done) => {
  done(null, user)
})
passport.deserializeUser( (user, done) => {
  done(null, user)
})

// Signin
// multi-form requests (login)
// (destination directory is required by multer, but not needed for login)
const multiFields = multer({
  dest: htmlPublic,
  limits: {
    fileSize: 0
  },
  fileFilter: (req, file, cb) => {
    cb(null, false);
  }
})

// Login request
app.post('/login', multiFields.fields([]), passport.authenticate('passport-local-plugin'),
  (req, res) => {
    res.status(200).send(req.user);
  });

// Auth Test
app.use('/auth', ensureLoggedIn.isRequired, (req, res) => {
  if (req.session.passport) {
    res.status(200).send(req.session.passport.user);
  } else {
    res.sendStatus(200);
  }
})

// Signout
app.use('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy();
  }
  req.logout();
  res.sendStatus(200);
})

// Static Data
app.use(serveStatic( htmlPublic, { index: ['index.html'] }));
app.use(serveStatic( cwd, { index: false }));

// create http2-server (spdy)
const server = spdy.createServer(sslSettings, app);
server.on('error', err => {
    if (err.code === 'EADDRINUSE') {
      console.error( `HTTP2 Server \n Port ${port} in use. Please check if node.exe is not already running on this port.` )
      server.close()
    } else if (err.code === 'EACCES') {
      console.error( `HTTP2 Server \n Network not accessable. Port ${port} might be in use by another application. Try to switch the port or quit the application, which is using this port` )
    } else {
      console.error( err.stack )
    }
  })
  .once('listening', () => {
    console.info( `HTTP2 Server is listening on port ${port}` )
  });

// socket.io
const io = require('socket.io')(server)
io.use((socket, next) => {
  cookieParser(socket.handshake, {}, err => {
    if (err) {
      console.log('socket.io: error in parsing cookie')
      return next(err)
    }
    if (!socket.handshake.signedCookies) {
      // console.log('no secureCookies|signedCookies found')
      return next(new Error('socket.io: no secureCookies found'))
    }
    if (!err && socket.handshake.signedCookies) {
      sessionStore.get(socket.handshake.signedCookies['connect.sid'], (err, session) => {
        socket.session = session
        // if (!err && !session) {
        //   err = 'Session not found';
        // }
        if (err) {
          console.warn(`socket.io: failed connection to socket.io\n ${err.stack}`)
        } else if (session) {
          // console.log('Successful connection to socket.io', session)
          next()
        }
      })
    } else {
      next(false)
    }
  })
})

// start the server
server.listen(port);

function copy(origin, dest) {
  return new Promise( (resolve, reject) => {
    fs.readFile(origin, 'utf8', (err, data) => {
      if (err) reject(`Transfer File failed \nfrom ${origin} \nto ${dest}\n ${err}`)
      fs.writeFile(dest, data, 'utf8', error => {
        if (error) reject(`Transfer File failed \nfrom ${origin} \nto ${dest}\n ${err}`)
        resolve(`Transfer File successful \nfrom ${origin} \nto ${dest}`)
      })
    })
  })
}
