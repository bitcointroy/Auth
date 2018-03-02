/* eslint-disable */
const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const User = require('./user.js');
const router = express.Router();
const cors = require('cors');

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;
const corsOptions = {
	origin: 'http://localhost:3000',
	credentials: true
};

const server = express();

server.use(cors(corsOptions));
server.use(bodyParser.json());
server.use(
	session({
		secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re',
		resave: true,
		saveUninitialized: true
	})
);

const validateCredentials = (req, res, next) => {
	const username = req.body.username;
	if (!req.body.password) {
		sendUserError('Must provide a username and password - 123', res);
		return;
	}
	User.findOne({ username })
		.then(user => {
			bcrypt.compare(req.body.password, user.passwordHash, (err, isValid) => {
				if (err) {
					sendUserError(err, res);
					return;
				}
				if (!isValid) {
					req.session.isLoggedIn = false;
					sendUserError(err, res);
				} else {
					req.session.user = user._id;
					req.session.isLoggedIn = true;
					next();
				}
			});
		})
		.catch(err => {
			sendUserError(err, res);
		});
};

const isLoggedIn = (req, res, next) => {
	if (req.session.isLoggedIn) {
		// User.findOne({ _id: req.session.user }).then(foundUser => {
		// 	req.user = foundUser;
		// 	next();
		// });
		next();
	} else {
		sendUserError('Please log in.', res);
	}
};

server.use('/restricted/*', (req, res, next) => {
	console.log('welcome VIP ...', req.session);
	if (req.session.isLoggedIn) {
		next();
		// res.json({ success: true });
	} else {
		sendUserError("Couldn't validate credentials.", res);
	}
});

server.get('/restricted/users', (req, res) => {
	console.log('VIPs only', req.session);
	User.find({})
		// .select('username')
		.then(users => {
			res.send(users);
		});
});
// User.find({})
// 	.then(users => {
// 		res.send(users);
// 		next();
// 	})
// .catch(err => sendUserError(err, res));

// server.use(Restricted middleware)

const sendUserError = (err, res) => {
	res.status(STATUS_USER_ERROR);
	if (err && err.message) {
		res.json({ message: err.message, stack: err.stack });
	} else {
		res.json({ error: err });
	}
};

// server.get('/restricted/users', isLoggedIn, (req, res) => {
// 	if (isLoggedIn === true) {
// 		User.find()
// 			.then(retrievedInfo => {
// 				res.status(200).json(retrievedInfo);
// 			})
// 			.catch(err => {
// 				sendUserError('Could not find any users.', res);
// 			});
// 	}
// });

server.post('/users', (req, res) => {
	const userInformation = req.body;
	if (!req.body.username || !req.body.password) {
		sendUserError('Please provide a username and password.', res);
		return;
	}

	req.body.passwordHash = bcrypt.hashSync(req.body.password, BCRYPT_COST);
	const user = new User(userInformation);
	user
		.save()
		.then(newUser => {
			res.status(200).json(newUser);
		})
		.catch(err => {
			sendUserError('Error saving user to the database.', res);
		});
});

server.post('/login', validateCredentials, (req, res) => {
	if (req.session.isLoggedIn) {
		if (!req.user) {
			req.user = req.body._id;
		}
		console.log('welcome ...', req.session);
		res.json({ success: true });
	} else {
		sendUserError("Couldn't validate credentials.", res);
	}
});

server.post('/logout', (req, res) => {
	if (req.session.isLoggedIn) {
		req.session.isLoggedIn = false;
		res.status(200).json('You have successfully logged out.');
	} else {
		sendUserError("Couldn't validate credentials. Are you logged in?", res);
	}
});

// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', isLoggedIn, (req, res) => {
	// Do NOT modify this route handler in any way.
	res.json(req.user);
});

module.exports = { server };
