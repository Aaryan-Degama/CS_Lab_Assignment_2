// Tiny JSON-file "database" shared by both the vulnerable and fixed
// servers. Kept deliberately simple (no real DB) so the assignment's
// dependencies stay minimal - the vulnerability under test is about data
// IN TRANSIT, not how it's stored, so a JSON file is fine for a demo.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const USERS_FILE = path.join(__dirname, "users.json");

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function initUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    const users = [{ username: "alice", passwordHash: sha256("password123") }];
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  }
}

function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
}

function verifyLogin(username, password) {
  const users = loadUsers();
  const user = users.find((u) => u.username === username);
  if (!user) return false;
  return user.passwordHash === sha256(password || "");
}

module.exports = { initUsers, verifyLogin, sha256 };
