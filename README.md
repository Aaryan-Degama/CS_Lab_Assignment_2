# Problem 19 — Cleartext Transmission of Sensitive Data (Node.js / Express)

A small Express "SecureBank" login demo built for Assignment-2 (Cyber
Security, July–Dec 2026, Section-B). It deliberately contains the assigned
vulnerability so the flaw, its exploitation, and its fix can all be
demonstrated on video as required by the assignment.

This is a Node/Express port of the equivalent Python/Flask version - same
behaviour, same demo flow.

> This video's link: **https://drive.google.com/file/d/1ZeLBOkVeWTJk9zHn4R5LtnPs35dMZ63H/view?usp=sharing**<br>
> Group ID: **20**

## The vulnerability

The app runs a normal-looking username/password login form. The flaw is not
in any single line of application logic — it's in how the server is
started: `server.js` listens over **plain HTTP**, with no TLS/SSL at all.
Because the connection between the browser and the server is unencrypted,
the login form's POST request — containing the raw username and password —
travels across the network as plaintext. Anyone who can observe traffic on
the path (same Wi-Fi network, a compromised router, an attacker doing ARP
spoofing on the LAN) can capture the packets with a tool like Wireshark or
`tcpdump` and read the credentials straight off the wire. No cracking, no
guessing — the data is just sitting there in the open.

Note this is distinct from how the password is *stored*: the app hashes
passwords with SHA-256 before comparing them (see `users-db.js`), so a
stolen copy of `users.json` doesn't hand over plaintext passwords. The
vulnerability here is specifically about **data in transit**, not data at
rest.

Files:
- `server.js` — the vulnerable app (plain HTTP, port 5000)
- `secure-server.js` — the fixed app (HTTPS via an in-memory self-signed
  cert, port 5443)
- `users-db.js` — shared JSON-file "database" + password hashing
- `views/`, `public/` — shared EJS templates and stylesheet for both
  versions
- `package.json` — dependencies

## Installation

Requires Node.js 18+ and npm.

```bash
git clone https://github.com/Aaryan-Degama/CS_Lab_Assignment_2.git
cd problem19-cleartext-transmission
npm install
```

## Running the vulnerable version

```bash
npm start
# or: node server.js
```

Visit `http://localhost:5000` (note: `http`, not `https`). Log in with the
demo account:

- Username: `alice`
- Password: `password123`

## Demonstrating the attack (for your screen recording)

You need a way to capture traffic on the loopback/local interface. Two
common options:

**Option A — Wireshark (GUI, easiest to show on screen)**
1. Install Wireshark.
2. Start a capture on the `Loopback` interface (`lo0` on macOS, `Loopback`
   adapter or `Npcap Loopback Adapter` on Windows, `lo` on Linux). If
   running the server on a separate VM/device, capture on the network
   interface those two machines share instead, and browse to the server's
   LAN IP rather than `localhost`.
3. Set a display filter: `http.request.method == "POST"`
4. In the browser, go to `http://localhost:5000`, submit the login form
   with the demo credentials.
5. In Wireshark, find the `POST /login` packet, right-click → **Follow →
   HTTP Stream**. The stream will show `username=alice&password=password123`
   in plain readable text — this is the exploit: no active attack step is
   needed beyond passively watching the wire.

**Option B — tcpdump (CLI)**
```bash
sudo tcpdump -i lo -A -s 0 'tcp port 5000' | grep -A5 "username="
```
Then submit the login form in the browser and watch the terminal print the
raw `username=...&password=...` body.

For the video: run the app normally first and walk through the code/UI
without revealing the flaw, *then* start the capture, submit the login
form, and show the plaintext credentials appearing in Wireshark/tcpdump.

## Running the fixed version

```bash
npm run start:secure
# or: node secure-server.js
```

Visit `https://localhost:5443`. Your browser will warn about an untrusted
certificate — that's expected, since the server generates a temporary
self-signed certificate in memory for the demo via the `selfsigned`
package (click through the warning, e.g. "Advanced → Proceed"). Repeat the
same Wireshark/tcpdump capture: the `POST /login` request is now inside an
encrypted TLS record, so following the stream shows ciphertext instead of
a readable `username=...&password=...` body. You'll also see in the
response headers that the session cookie now carries `Secure`, `HttpOnly`,
and `SameSite=Lax` flags.

## The fix, explained

Two changes turn `server.js` into `secure-server.js`:

1. **Encrypt the transport.** Instead of `app.listen(...)` directly, the
   Express app is wrapped in `https.createServer({ key, cert }, app)` with
   a TLS certificate (a self-signed one generated in memory for this demo;
   in production you'd use a certificate from a trusted CA such as Let's
   Encrypt, typically terminated at a reverse proxy like nginx). This alone
   means every byte between browser and server — including the login form
   submission — is encrypted before it touches the network, so packet
   capture yields only ciphertext.
2. **Lock down the session cookie.** The session middleware's `cookie`
   option sets `secure: true` (the cookie is only ever sent back over
   HTTPS, never leaked over a stray plain HTTP request) and `httpOnly:
   true` (keeps it out of reach of JavaScript, closing a related exposure
   path), plus `sameSite: "lax"` to reduce cross-site leakage.

In a real deployment you'd also want to redirect any stray HTTP request to
HTTPS (e.g. via `Strict-Transport-Security` / HSTS) so a user typing the
bare domain never even briefly hits the unencrypted version.

## Notes

- `users.json` is created automatically on first run and seeded with the
  `alice` / `password123` demo account. It's git-ignored.
- Do not deploy `server.js` (the vulnerable version) anywhere reachable
  from an untrusted network — run it only on localhost or an isolated lab
  network/VM pair for this demonstration.
