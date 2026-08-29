/**
 * FIXED VERSION - Problem 19: Cleartext Transmission of Sensitive Data
 * ------------------------------------------------------------------------
 * Same application logic as server.js, but with the fix applied:
 *
 * 1. The server is wrapped in `https.createServer()` with a TLS
 *    certificate, so all traffic (including the login form submission)
 *    is encrypted between the browser and the server. An observer
 *    capturing packets now sees only encrypted TLS records, not the
 *    plaintext username/password.
 * 2. The session cookie is marked `secure: true` (only ever sent back
 *    over HTTPS) and `httpOnly: true` (not accessible to JavaScript,
 *    reducing XSS-driven theft), with `sameSite: "lax"` to reduce
 *    cross-site leakage.
 *
 * For this demo, the `selfsigned` package generates a temporary
 * self-signed certificate in memory, so there's nothing extra to install
 * or configure. Your browser will show a certificate warning because the
 * certificate isn't from a trusted CA - that's expected for a local demo.
 * In a real deployment you'd use a certificate from a trusted CA (e.g.
 * Let's Encrypt), typically terminated at a reverse proxy such as nginx.
 */

const express = require("express");
const session = require("express-session");
const path = require("path");
const https = require("https");
const selfsigned = require("selfsigned");
const { initUsers, verifyLogin } = require("./users-db");

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

// --- Fix, part 1: cookie only ever travels over an encrypted connection ---
app.use(
  session({
    secret: "dev-secret-key-not-for-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "lax",
    },
  }),
);

app.get("/", (req, res) => {
  if (req.session.username) return res.redirect("/dashboard");
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (verifyLogin(username, password)) {
    req.session.username = username;
    return res.redirect("/dashboard");
  }
  res.render("login", { error: "Invalid username or password" });
});

app.get("/dashboard", (req, res) => {
  if (!req.session.username) return res.redirect("/");
  res.render("dashboard", { username: req.session.username });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

initUsers();

// --- Fix, part 2: serve over TLS instead of plain HTTP ---
const attrs = [{ name: "commonName", value: "localhost" }];
// generate a 2048-bit RSA key to satisfy modern OpenSSL security levels
const pems = selfsigned.generate(attrs, { days: 365, keySize: 2048 });

https
  .createServer({ key: pems.private, cert: pems.cert }, app)
  .listen(5443, "0.0.0.0", () => {
    console.log(
      "Fixed app running at https://localhost:5443 (TLS, self-signed cert)",
    );
  });
