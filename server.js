/**
 * Problem 19: Cleartext Transmission of Sensitive Data
 * ------------------------------------------------------
 * DELIBERATELY VULNERABLE DEMO APPLICATION - for coursework use only.
 *
 * This server listens on plain HTTP (no TLS/SSL - see app.listen at the
 * bottom, compare to secure-server.js which wraps the same app in
 * https.createServer). Because the connection is unencrypted, the
 * username and password submitted by the login form travel across the
 * network as plaintext bytes inside the HTTP POST body. Anyone who can
 * observe the traffic - someone on the same Wi-Fi network, a compromised
 * router in the path, or an attacker doing ARP spoofing on the LAN - can
 * capture the packets with Wireshark or tcpdump and read the credentials
 * directly, with no cracking or guessing required.
 *
 * Do NOT deploy this application anywhere reachable from an untrusted
 * network. Run it only on localhost / an isolated lab network.
 */

const express = require("express");
const session = require("express-session");
const path = require("path");
const { initUsers, verifyLogin } = require("./users-db");

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "dev-secret-key-not-for-production", // fine for a local demo only
    resave: false,
    saveUninitialized: false,
    // No `cookie: { secure: true }` here - the session cookie is happily
    // sent back over plain HTTP too, same weakness as the credentials.
  })
);

app.get("/", (req, res) => {
  if (req.session.username) return res.redirect("/dashboard");
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  // --- THE VULNERABILITY LIVES HERE ---
  // These two fields arrive as a plain HTTP POST body. Because this
  // server has no SSL/TLS context, this exact request travels the
  // network unencrypted.
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

// Deliberately plain HTTP - no TLS - so the traffic can be captured for
// the demonstration. Bound to 0.0.0.0 so it's reachable from another
// device on the same lab network if you want to capture from there
// instead of localhost.
app.listen(5000, "0.0.0.0", () => {
  console.log("Vulnerable app running at http://localhost:5000 (plain HTTP)");
});
