require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");

const app = express();
const port = 3000;
const saltRounds = 12;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`;
const client = new MongoClient(atlasURI);
const userCollection = client.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions?retryWrites=true&w=majority`,
  collectionName: "sessions",
  // removed crypto — it's causing a bug with this version of connect-mongo
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: 60 * 60 * 1000 }, // 1 hour
  }),
);

// ── HOME PAGE ────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
      <h1>Welcome</h1>
      <a href="/signup"><button>Sign up</button></a><br><br>
      <a href="/login"><button>Log in</button></a>
    `);
  } else {
    res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <a href="/members"><button>Go to Members Area</button></a><br><br>
      <a href="/logout"><button>Logout</button></a>
    `);
  }
});

// ── SIGN UP PAGE ─────────────────────────────────────────────────────
app.get("/signup", (req, res) => {
  res.send(`
    <h2>create user</h2>
    <form action='/signupSubmit' method='post'>
      <input name='name' placeholder='name'><br><br>
      <input name='email' placeholder='email'><br><br>
      <input name='password' type='password' placeholder='password'><br><br>
      <button type='submit'>Submit</button>
    </form>
  `);
});

// ── SIGN UP SUBMIT ───────────────────────────────────────────────────
app.post("/signupSubmit", async (req, res) => {
  const { name, email, password } = req.body;

  // Validate inputs with Joi (prevents NoSQL injection)
  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const result = schema.validate({ name, email, password });
  if (result.error) {
    const msg = result.error.details[0].message;
    return res.send(`<p>${msg}</p><a href='/signup'>Try again</a>`);
  }

  // Hash password before storing
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  // Save session then redirect
  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;

  req.session.save((err) => {
    if (err) {
      console.error("Session save error:", err);
    }
    res.redirect("/members");
  });
});

// ── LOGIN PAGE ───────────────────────────────────────────────────────
app.get("/login", (req, res) => {
  res.send(`
    <h2>log in</h2>
    <form action='/loginSubmit' method='post'>
      <input name='email' placeholder='email'><br><br>
      <input name='password' type='password' placeholder='password'><br><br>
      <button type='submit'>Submit</button>
    </form>
  `);
});

// ── LOGIN SUBMIT ─────────────────────────────────────────────────────
app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;

  // Validate inputs with Joi (prevents NoSQL injection)
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const result = schema.validate({ email, password });
  if (result.error) {
    return res.send(`<p>Invalid input.</p><a href='/login'>Try again</a>`);
  }

  // Find user by email
  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.send(
      `<p>Invalid email/password combination.</p><a href='/login'>Try again</a>`,
    );
  }

  // Compare password with BCrypted hash
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.send(
      `<p>Invalid email/password combination.</p><a href='/login'>Try again</a>`,
    );
  }

  // Save session then redirect
  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;

  req.session.save((err) => {
    if (err) {
      console.error("Session save error:", err);
    }
    res.redirect("/members");
  });
});

// ── MEMBERS PAGE ─────────────────────────────────────────────────────
app.get("/members", (req, res) => {
  console.log("Session at /members:", req.session); // temporary debug line

  if (!req.session.authenticated) {
    return res.redirect("/");
  }

  // Pick a random image from /public folder
  const images = ["image1.jpeg", "image2.jpeg", "image3.jpeg"];
  const random = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello, ${req.session.name}.</h1>
    <img src='/${random}' width='300'><br><br>
    <a href="/logout"><button>Sign out</button></a>
  `);
});

// ── LOGOUT ───────────────────────────────────────────────────────────
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// ── 404 PAGE (must be last!) ─────────────────────────────────────────
app.use((req, res) => {
  res.status(404).send("<h1>Page not found - 404</h1>");
});

// ── START SERVER (only after DB connects) ────────────────────────────
client
  .connect()
  .then(() => {
    console.log("Connected to MongoDB!");
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("Failed to connect to MongoDB", err);
  });
