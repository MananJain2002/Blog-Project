require("dotenv").config();
const express = require("express");
const https = require("https");
const fs = require("fs");
const ejs = require("ejs");
const _ = require("lodash");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const flash = require('connect-flash');
const { prototype } = require("nodemailer/lib/sendmail-transport");

const homeStartingContent =
	"Lacus vel facilisis volutpat est velit egestas dui id ornare. Semper auctor neque vitae tempus quam. Sit amet cursus sit amet dictum sit amet justo. Viverra tellus in hac habitasse. Imperdiet proin fermentum leo vel orci porta. Donec ultrices tincidunt arcu non sodales neque sodales ut. Mattis molestie a iaculis at erat pellentesque adipiscing. Magnis dis parturient montes nascetur ridiculus mus mauris vitae ultricies. Adipiscing elit ut aliquam purus sit amet luctus venenatis lectus. Ultrices vitae auctor eu augue ut lectus arcu bibendum at. Odio euismod lacinia at quis risus sed vulputate odio ut. Cursus mattis molestie a iaculis at erat pellentesque adipiscing.";
const aboutContent =
	"Hac habitasse platea dictumst vestibulum rhoncus est pellentesque. Dictumst vestibulum rhoncus est pellentesque elit ullamcorper. Non diam phasellus vestibulum lorem sed. Platea dictumst quisque sagittis purus sit. Egestas sed sed risus pretium quam vulputate dignissim suspendisse. Mauris in aliquam sem fringilla. Semper risus in hendrerit gravida rutrum quisque non tellus orci. Amet massa vitae tortor condimentum lacinia quis vel eros. Enim ut tellus elementum sagittis vitae. Mauris ultrices eros in cursus turpis massa tincidunt dui.";
const contactContent =
	"Scelerisque eleifend donec pretium vulputate sapien. Rhoncus urna neque viverra justo nec ultrices. Arcu dui vivamus arcu felis bibendum. Consectetur adipiscing elit duis tristique. Risus viverra adipiscing at in tellus integer feugiat. Sapien nec sagittis aliquam malesuada bibendum arcu vitae. Consequat interdum varius sit amet mattis. Iaculis nunc sed augue lacus. Interdum posuere lorem ipsum dolor sit amet consectetur adipiscing elit. Pulvinar elementum integer enim neque. Ultrices gravida dictum fusce ut placerat orci nulla. Mauris in aliquam sem fringilla ut morbi tincidunt. Tortor posuere ac ut consequat semper viverra nam libero.";

const app = express();

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());

const createTransporter = async () => {
	const oauth2Client = new OAuth2(
		process.env.GOOGLE_CLIENT_ID,
		process.env.GOOGLE_CLIENT_SECRET,
		"https://developers.google.com/oauthplayground"
	);

	oauth2Client.setCredentials({
		refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
	});

	const accessToken = await new Promise((resolve, reject) => {
		oauth2Client.getAccessToken((err, token) => {
			if (err) {
				reject("Failed to create access token :(");
			}
			resolve(token);
		});
	});

	const transporter = nodemailer.createTransport({
		service: "gmail",
		auth: {
			type: "OAuth2",
			user: process.env.EMAIL,
			accessToken,
			clientId: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			refreshToken: process.env.GOOGLE_REFRESH_TOKEN,
		},
	});
	return transporter;
};

const sendEmail = async (emailOptions) => {
	let emailTransporter = await createTransporter();
	await emailTransporter.sendMail(emailOptions);
};

app.use(
	session({
		secret: "Hi, It's me Mario.",
		resave: false,
		saveUninitialized: false,
	})
);

app.use(flash());

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODB_URL);

const userSchema = new mongoose.Schema({
	username: String,
	passwordYes: Number,
	name: String,
	googleId: String,
	facebookId: String,
	twitterId: String,
	userPosts: Array,
});

const postSchema = new mongoose.Schema({
	title: String,
	content: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

const Post = mongoose.model("Post", postSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			callbackURL: "https://localhost:3000/auth/google/blog",
			userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
		},
		function (accessToken, refreshToken, profile, cb) {
			User.findOne(
				{
					username: profile.emails[0].value,
				},
				function (err, user) {
					if (err) {
						return cb(err);
					}
					if (!user) {
						user = new User({
							name: profile.name.givenName,
							username: profile.emails[0].value,
							googleId: profile.id,
						});
						user.save(function (err) {
							if (err) console.log(err);
							return cb(err, user);
						});
					} else {
						User.findOneAndUpdate(
							{ username: profile.emails[0].value },
							{ googleId: profile.id },
							(err, user) => {
								if (err) {
									console.log(err);
								} else {
									return cb(err, user);
								}
							}
						);
					}
				}
			);
		}
	)
);

passport.use(
	new FacebookStrategy(
		{
			clientID: process.env.FACEBOOK_APP_ID,
			clientSecret: process.env.FACEBOOK_APP_SECRET,
			callbackURL: "https://localhost:3000/auth/facebook/blog",
			profileFields: ["id", "emails", "name"],
		},
		function (accessToken, refreshToken, profile, cb) {
			// User.findOrCreate({ facebookId: profile.id, name: profile.name.givenName, username: profile.emails[0].value }, function (err, user) {
			// 	return cb(err, user);
			// });
			User.findOne(
				{
					username: profile.emails[0].value,
				},
				function (err, user) {
					if (err) {
						return cb(err);
					}
					if (!user) {
						user = new User({
							name: profile.name.givenName,
							username: profile.emails[0].value,
							facebookId: profile.id,
						});
						user.save(function (err) {
							if (err) console.log(err);
							return cb(err, user);
						});
					} else {
						User.findOneAndUpdate(
							{ username: profile.emails[0].value },
							{ facebookId: profile.id },
							(err, user) => {
								if (err) {
									console.log(err);
								} else {
									return cb(err, user);
								}
							}
						);
					}
				}
			);
		}
	)
);

passport.use(
	new TwitterStrategy(
		{
			consumerKey: process.env.TWITTER_API_KEY,
			consumerSecret: process.env.TWITTER_API_SECRET,
			callbackURL: "https://localhost:3000/auth/twitter/blog",
			userProfileURL:
				"https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true",
			passReqToCallback: true,
		},
		function (token, tokenSecret, profile, cb) {
			// User.findOrCreate({ twitterId: profile.id, name: "f", username: profile.emails[0].value }, function (err, user) {
			// 	return cb(err, user);
			// });
			User.findOne(
				{
					username: profile.emails[0].value,
				},
				function (err, user) {
					if (err) {
						return cb(err);
					}
					if (!user) {
						user = new User({
							name: profile.name.givenName,
							username: profile.emails[0].value,
							twitterId: profile.id,
						});
						user.save(function (err) {
							if (err) console.log(err);
							return cb(err, user);
						});
					} else {
						User.findOneAndUpdate(
							{ username: profile.emails[0].value },
							{ twitterId: profile.id },
							(err, user) => {
								if (err) {
									console.log(err);
								} else {
									return cb(err, user);
								}
							}
						);
					}
				}
			);
		}
	)
);

app.get("/", function (req, res) {
	res.set("Cache-Control", "no-store");
	if (req.isAuthenticated()) {
		User.find({ userPosts: { $ne: null } }, (err, postArray) => {
			if (err) {
				console.log(err);
			} else {
				if (postArray) {
					res.render("home", {
						startingContent: homeStartingContent,
						posts: req.user.userPosts,
						name: req.user.name,
					});
				}
			}
		});
	} else {
		res.redirect("/login");
	}
});

app.get(
	"/auth/google",
	passport.authenticate("google", {
		scope: [
			"profile",
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		],
	})
);

app.get(
	"/auth/google/blog",
	passport.authenticate("google", { failureRedirect: "/login" }),
	function (req, res) {
		// Successful authentication, redirect home.
		res.redirect("/");
	}
);

app.get(
	"/auth/facebook",
	passport.authenticate("facebook", {
		// scope: "public_profile",
		scope: ["email"],
	})
);

app.get(
	"/auth/facebook/blog",
	passport.authenticate("facebook", { failureRedirect: "/login" }),
	function (req, res) {
		// Successful authentication, redirect home.
		res.redirect("/");
	}
);

app.get("/auth/twitter", passport.authenticate("twitter"));

app.get(
	"/auth/twitter/blog",
	passport.authenticate("twitter", { failureRedirect: "/login" }),
	function (req, res) {
		// Successful authentication, redirect home.
		res.redirect("/");
	}
);

app.get("/login", (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect("/")
	} else {
		const failureFlash = req.flash("error");
		res.render("login", {failureFlash});
	}
});

app.get("/register", (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect("/");
	} else {
		const message = req.flash("exist")
		res.render("register", {message});
	}
});

app.get("/about", function (req, res) {
	res.set("Cache-Control", "no-store");
	if (req.isAuthenticated()) {
		res.render("about", { aboutContent: aboutContent, name: req.user.name });
	} else {
		res.redirect("/login");
	}
});

app.get("/contact", function (req, res) {
	res.set("Cache-Control", "no-store");
	if (req.isAuthenticated()) {
		res.render("contact", {
			contactContent: contactContent,
			name: req.user.name,
		});
	} else {
		res.redirect("/login");
	}
});

app.get("/compose", function (req, res) {
	res.set("Cache-Control", "no-store");
	if (req.isAuthenticated()) {
		res.render("compose", { name: req.user.name });
	} else {
		res.redirect("/login");
	}
});

app.get("/posts/:postId", function (req, res) {
	res.set("Cache-Control", "no-store");
	if (req.isAuthenticated()) {
		const requestedPostId = req.params.postId;
		req.user.userPosts.some((post) => {
			if (post._id.equals(requestedPostId)) {
				res.render("post", {
					title: post.title,
					content: post.content,
					name: req.user.name,
					requestedPostId: requestedPostId,
				});
				return true;
			}
		});
	} else {
		res.redirect("/login");
	}
});

app.get("/changeName", (req, res) => {
	if(req.isAuthenticated()) {
		const message = req.flash("error");
		res.render("changeName", {message});
	} else {
		res.redirect("/");
	}
})

app.get("/changePassword", (req, res) => {
	if (req.isAuthenticated()) {
		if(req.user.passwordYes) {
			const message = req.flash("error");
			res.render("changePassword", {message});
		} else {
			res.redirect("/");
		}
	} else {
		res.redirect("/");
	}
});

app.get("/forgotPassword", (req, res) => {
	const message = req.flash("error");
	res.render("recieveEmail", {message});
})

app.get("/logout", (req, res) => {
	req.logout();
	res.redirect("/");
});

app.post("/", (req, res) => {
	User.findOneAndUpdate(
		{ _id: req.user._id },
		{ $pull: { userPosts: { _id: mongoose.Types.ObjectId(req.body.postId)} } },
		{ new: true }
		)
		.then(user => user.save())
		.catch(err => console.log(err));

	res.redirect("/");
});

app.post("/compose", (req, res) => {
	const post = new Post({
		title: req.body.postTitle,
		content: req.body.postBody,
	});

	req.user.userPosts.push(post);

	req.user.save((err) => {
		if (!err) {
			res.redirect("/");
		}
	});
});

app.post("/changeName", (req, res) => {
	if(req.body.Name.length <= 30) {
		User.findOneAndUpdate({name: req.user.name}, {name: req.body.Name}, (err) => {
			if(err) {
				console.log(err);
			} else {
				res.redirect("/");
			}
		});
	} else {
		req.flash("error", "Name cannot be more than 30 letters");
		res.redirect("/changeName");
	}
});

app.post("/changePassword", (req, res) => {

	if(req.body.new === req.body.confirm) {

		if(req.body.old === req.body.new) {
			req.flash("error", "Password must differ from old password!");
			res.redirect("/changePassword");
		} else {
			User.findOne({ username: req.user.username }, (err, user) => {
				if (err) {
					res.json({ success: false, message: err });
				} else {
					if (!user) {
						res.json({ success: false, message: "User not found" });
					} else {
						user.changePassword(req.body.old, req.body.new, function (err) {
							if (err) {
								if (err.name === "IncorrectPasswordError") {
									req.flash("error", "Wrong Password!");
									res.redirect("/changePassword");
									// res.json({ success: false, message: "Incorrect password" });
								} else {
									res.json({
										success: false,
										message:
											"Something went wrong!! Please try again after sometimes.",
									});
								}
							} else {
								res.redirect("/");
							}
						});
					}
				}
			});
		}
	} else {
		req.flash("error", "Passwords does not match!");
		res.redirect("/changePassword");
	}
});

const otpP= Math.floor(100000 + Math.random() * 900000);

app.post("/forgotPassword", (req, res) => {
	if(req.body.emailCheck) {
		User.findOne({username: req.body.username}, (err, user) => {
			if (user){
				sendEmail({
					subject: "Test",
					text: "I am sending an email from nodemailer! " + otpP,
					to: user.username,
					from: process.env.EMAIL,
				});
				res.render("confirmP", {username: user.username})
			} else {
				req.flash("error", "User does not exist");
				res.redirect("/forgotPassword");
			}
		});
	}
	if (req.body.pageCheck) {
		if (Number(req.body.otp) === otpP) {
			const message = req.flash("error");
			res.render("forgotPassword", {username: req.body.username, message});
		} else {
			res.render("confirmP", {username: req.body.username});
		}
	}
	if(req.body.forgotPage) {
		if(req.body.new === req.body.confirm) {
			User.findByUsername(req.body.username).then(function(sanitizedUser){
				if (sanitizedUser){
					sanitizedUser.setPassword(req.body.new, function(){
						sanitizedUser.save();
						res.redirect("/");
					});
				} else {
					res.status(500).json({message: 'This user does not exist'});
				}
			},function(err){
				console.error(err);
			});
		} else {
			req.flash("error", "Password does not match!");
			const message = req.flash("error");
			res.render("forgotPassword", {username: req.body.username, message});
		}
	}
});

app.post('/login',
  passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: true, failureFlash: 'Invalid username or passwerd.'}));

passport.authenticate('local', { failureFlash: 'Invalid username or password.' });

var verified = 0;
const otp = Math.floor(100000 + Math.random() * 900000);

app.post("/register", (req, res) => {
	if (Number(req.body.pageCheck)) {
		if (Number(req.body.otp) === otp) {
			verified = 1;
		} else {
			const username = req.body.username;
			const password = req.body.password;
			const name = req.body.FirstName;
			res.render("confirm", {
				email: username,
				password: password,
				name: name,
			});
		}
	}
	if (!verified) {
		if (req.body.password === req.body.ConfirmPassword) {
			const username = req.body.username;
			const password = req.body.password;
			const name = req.body.FirstName;
			User.findByUsername(req.body.username).then(
				function (sanitizedUser) {
					if(sanitizedUser) {
						if(sanitizedUser.passwordYes) {
							req.flash("exist", "User already exist");
							res.redirect("/register");
						} else {
							sendEmail({
								subject: "Test",
								text: "I am sending an email from nodemailer! " + otp,
								to: username,
								from: process.env.EMAIL,
							});
							res.render("confirm", {
								email: username,
								password: password,
								name: name,
							});
						}
					} else {
						sendEmail({
							subject: "Test",
							text: "I am sending an email from nodemailer! " + otp,
							to: username,
							from: process.env.EMAIL,
						});
						res.render("confirm", {
							email: username,
							password: password,
							name: name,
						});
					}
				}
			)
		} else {
			res.redirect("/register");
		}
	} else {
		verified = 0;
		User.findByUsername(req.body.username).then(
			function (sanitizedUser) {
				if (sanitizedUser) {
					User.findOneAndUpdate(
						{ username: req.body.username },
						{ passwordYes: 1 },
						(err) => {
							if (err) {
								console.log(err);
							}
						}
					);
					sanitizedUser.setPassword(req.body.password, function () {
						sanitizedUser.save();
						passport.authenticate("local")(req, res, () => {
							res.redirect("/");
						});
					});
				} else {
					User.register(
						{ username: req.body.username, name: req.body.FirstName, passwordYes: 1 },
						req.body.password,
						(err, user) => {
							if (err) {
								console.log(err);
								res.redirect("/register");
							} else {
								passport.authenticate("local")(req, res, () => {
									res.redirect("/");
								});
							}
						}
					);
				}
			},
			function (err) {
				console.error(err);
			}
		);
	}
});

const options = {
	key: fs.readFileSync(__dirname + "/security/server.key"),
	cert: fs.readFileSync(__dirname + "/security/server.cert"),
};

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

https.createServer(options, app).listen(port, function (req, res) {
	console.log("Server started successfully");
});
