require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;
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

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions?retryWrites=true&w=majority`,
  collectionName: "sessions",
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: 60 * 60 * 1000 },
  }),
);

// Home Page
app.get("/", (req, res) => {
  res.render("index", {
    authenticated: req.session.authenticated || false,
    name: req.session.name || "",
  });
});

// Sign Up Page
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

// Sign Up Submit
app.post("/signupSubmit", async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const result = schema.validate({ name, email, password });
  if (result.error) {
    return res.render("signup", { error: result.error.details[0].message });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.user_type = "user";

  req.session.save((err) => {
    if (err) console.error("Session save error:", err);
    res.redirect("/members");
  });
});

// Login Page
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// Login Submit
app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const result = schema.validate({ email, password });
  if (result.error) {
    return res.render("login", { error: "Invalid input." });
  }

  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.render("login", {
      error: "Invalid email/password combination.",
    });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.render("login", {
      error: "Invalid email/password combination.",
    });
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;
  req.session.user_type = user.user_type;

  req.session.save((err) => {
    if (err) console.error("Session save error:", err);
    res.redirect("/members");
  });
});

// Members Page
app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/");
  }
  res.render("members", { name: req.session.name });
});

// Admin Page
app.get("/admin", async (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  if (req.session.user_type !== "admin") {
    return res.status(403).render("403");
  }
  const users = await userCollection.find().toArray();
  res.render("admin", { users });
});

// Promote User
app.get("/promoteUser", async (req, res) => {
  const schema = Joi.object({ email: Joi.string().email().required() });
  const result = schema.validate({ email: req.query.email });
  if (result.error) return res.status(400).send("Invalid input.");

  await userCollection.updateOne(
    { email: req.query.email },
    { $set: { user_type: "admin" } },
  );
  res.redirect("/admin");
});

// Demote User
app.get("/demoteUser", async (req, res) => {
  const schema = Joi.object({ email: Joi.string().email().required() });
  const result = schema.validate({ email: req.query.email });
  if (result.error) return res.status(400).send("Invalid input.");

  await userCollection.updateOne(
    { email: req.query.email },
    { $set: { user_type: "user" } },
  );
  res.redirect("/admin");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404 Page
app.use((req, res) => {
  res.status(404).render("404");
});

// Start Server
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
