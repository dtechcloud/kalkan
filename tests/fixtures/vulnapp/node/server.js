"use strict";

const childProcess = require("child_process");
const crypto = require("crypto");

const cookieParser = require("cookie-parser");
const cors = require("cors");
const escapeHtml = require("escape-html");
const express = require("express");
const jwt = require("jsonwebtoken");
const libxmljs = require("libxmljs");
const _ = require("lodash");
const minimist = require("minimist");
const { MongoClient } = require("mongodb");
const mysql = require("mysql");
const serialize = require("node-serialize");

const { evaluateArithmetic } = require("./lib/arith");
const { deepMerge, mergeSettings } = require("./lib/merge");

const argv = minimist(process.argv.slice(2));
const PUBLIC_KEY = process.env.VULNAPP_JWT_PUBLIC_KEY || "";
const CARD_KEY = Buffer.from(process.env.VULNAPP_CARD_KEY || "", "hex");
const RETURN_PAGES = { cart: "/cart", orders: "/orders", profile: "/profile" };
const GREETING_TEMPLATE = "<p>Hello <%- name %>!</p>";

const app = express();
const db = mysql.createPool(process.env.VULNAPP_MYSQL_URL || "mysql://localhost/vulnapp");
const mongo = new MongoClient(process.env.VULNAPP_MONGO_URL || "mongodb://localhost:27017");
const users = mongo.db("vulnapp").collection("users");
const preferences = {};
const sections = new Map([
  ["display", new Map()],
  ["mail", new Map()],
]);

app.use(express.json());
app.use(express.text({ type: "application/xml" }));
app.use(cookieParser());
app.use("/api/partner", cors({ origin: "*", credentials: true }));

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function hashPasswordV2(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function sealCardNumber(number) {
  const cipher = crypto.createCipheriv("aes-256-ecb", CARD_KEY, null);
  return Buffer.concat([cipher.update(number, "utf8"), cipher.final()]).toString("base64");
}

function sealCardNumberV2(number) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", CARD_KEY, iv);
  const sealed = Buffer.concat([cipher.update(number, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), sealed]).toString("base64");
}

app.get("/hello", (req, res) => {
  res.send(`<p>Hello ${req.query.name}!</p>`);
});

app.get("/hello/v2", (req, res) => {
  res.send(`<p>Hello ${escapeHtml(req.query.name)}!</p>`);
});

app.post("/api/users/lookup", async (req, res) => {
  const user = await users.findOne({ username: req.body.username });
  res.json({ found: Boolean(user) });
});

app.post("/api/users/exists", async (req, res) => {
  const user = await users.findOne({ username: String(req.body.username) });
  res.json({ found: Boolean(user) });
});

app.post("/api/preferences", (req, res) => {
  deepMerge(preferences, req.body);
  res.json(preferences);
});

app.post("/api/preferences/v2", (req, res) => {
  mergeSettings(preferences, req.body);
  res.json(preferences);
});

app.post("/api/settings", (req, res) => {
  const { section, key, value } = req.body;
  preferences[section] = preferences[section] || {};
  preferences[section][key] = value;
  res.json({ ok: true });
});

app.post("/api/settings/v2", (req, res) => {
  const { section, key, value } = req.body;
  const store = sections.get(String(section));
  if (!store) {
    return res.status(400).json({ error: "unknown section" });
  }
  store.set(String(key), value);
  return res.json({ ok: true });
});

app.get("/login/continue", (req, res) => {
  res.redirect(req.query.next);
});

app.get("/logout/continue", (req, res) => {
  res.redirect(RETURN_PAGES[req.query.page] || "/");
});

app.get("/tools/ping", (req, res) => {
  childProcess.exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
    res.type("text/plain").send(stdout);
  });
});

app.get("/tools/ping/v2", (req, res) => {
  childProcess.execFile("ping", ["-c", "1", "--", String(req.query.host)], (err, stdout) => {
    res.type("text/plain").send(stdout);
  });
});

app.get("/api/account", (req, res) => {
  const token = String(req.headers.authorization || "").replace(/^Bearer /, "");
  const claims = jwt.verify(token, PUBLIC_KEY);
  res.json({ user: claims.sub });
});

app.get("/api/account/v2", (req, res) => {
  const token = String(req.headers.authorization || "").replace(/^Bearer /, "");
  const claims = jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });
  res.json({ user: claims.sub });
});

app.get("/api/orders/:id", (req, res) => {
  db.query("SELECT * FROM orders WHERE id = " + req.params.id, (err, rows) => {
    res.json(rows);
  });
});

app.get("/api/orders/:id/items", (req, res) => {
  db.query("SELECT * FROM order_items WHERE order_id = ?", [req.params.id], (err, rows) => {
    res.json(rows);
  });
});

app.post("/api/greeting", (req, res) => {
  const render = _.template(req.body.template);
  res.json({ html: render({ name: req.body.name }) });
});

app.post("/api/greeting/v2", (req, res) => {
  const render = _.template(GREETING_TEMPLATE);
  res.json({ html: render({ name: req.body.name }) });
});

app.get("/api/calc", (req, res) => {
  const result = eval(req.query.expr);
  res.json({ result });
});

app.get("/api/calc/v2", (req, res) => {
  const result = evaluateArithmetic(String(req.query.expr));
  res.json({ result });
});

app.get("/api/profile", (req, res) => {
  const profile = serialize.unserialize(Buffer.from(req.cookies.profile, "base64").toString());
  res.json({ name: profile.name });
});

app.get("/api/profile/v2", (req, res) => {
  const profile = JSON.parse(Buffer.from(req.cookies.profile, "base64").toString());
  res.json({ name: profile.name });
});

app.post("/api/import", (req, res) => {
  const doc = libxmljs.parseXml(req.body, { noent: true, nonet: false });
  res.json({ root: doc.root().name() });
});

app.post("/api/import/v2", (req, res) => {
  const doc = libxmljs.parseXml(req.body, { noent: false, nonet: true });
  res.json({ root: doc.root().name() });
});

app.post("/api/register", (req, res) => {
  const digest = hashPassword(req.body.password);
  db.query("INSERT INTO users (name, pw) VALUES (?, ?)", [req.body.name, digest], () => {
    res.json({ ok: true });
  });
});

app.post("/api/password", (req, res) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = hashPasswordV2(req.body.password, salt);
  db.query("UPDATE users SET pw = ?, salt = ? WHERE id = ?", [digest, salt, 1], () => {
    res.json({ ok: true });
  });
});

app.post("/api/cards", (req, res) => {
  res.json({ token: sealCardNumber(String(req.body.number)) });
});

app.post("/api/cards/v2", (req, res) => {
  res.json({ token: sealCardNumberV2(String(req.body.number)) });
});

app.use("/api/store", cors({ origin: ["https://shop.vulnapp.internal"], credentials: true }));

app.listen(Number(argv.port) || 3000);
