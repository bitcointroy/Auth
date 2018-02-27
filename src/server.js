const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const User = require('./user.js');

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;

const server = express();
// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(
	session({
		secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re',
		resave: true,
    	saveUninitialized: true
	})
);

/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */

const sendUserError = (err, res) => {
	res.status(STATUS_USER_ERROR);
	if (err && err.message) {
		res.json({ message: err.message, stack: err.stack });
	} else {
		res.json({ error: err });
	}
};

const validateCredentials = (req, res, next) => {
	const username = req.body.username;
	User.findOne({ username }).then((user) => {
		bcrypt.compare(req.body.password, user.passwordHash, (err, isValid) => {
			if (err) throw err;
			if (!isValid) {
				req.session.isLoggedIn = false;
				sendUserError(err, res);
			} else {
				req.session.user = username;
				req.session.isLoggedIn = true;
				next();
			}
		});
	})
	.catch((err) => {
		sendUserError(err, res);
	})
}

const isLoggedIn = (req, res, next) => {
	if (req.session.isLoggedIn) {
		req.user = req.session.user;
		next();
	} else {
		sendUserError('Please log in.', res);
	}
}

server.post('/users', (req, res) => {
	const userInformation = req.body;
	if (!req.body.username || !req.body.password) {
		sendUserError('Please provide a username and password.', res);
	}
	
	req.body.passwordHash = bcrypt.hashSync(req.body.password, BCRYPT_COST);
	const user = new User(userInformation);
	user.save()
		.then((newUser) => {
			res.status(201).json(newUser);
		})
		.catch((err) => {
			sendUserError('Error saving user to the database.', res);
		});
});

server.post('/log-in', validateCredentials, (req, res) => {
	if (req.session.isLoggedIn) {
		if (!req.user) {
			req.user = req.body.username;
		}
		res.json({success: true})
	} else {
		sendUserError('Couldn\'t validate credentials.', res)
	}
})

// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', isLoggedIn, (req, res) => {
	// Do NOT modify this route handler in any way.
	res.json(req.user);
});

module.exports = { server };
