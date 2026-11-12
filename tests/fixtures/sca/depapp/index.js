"use strict";
// kalkan depapp fixture. Never deploy.

const _ = require("lodash");
const minimist = require("minimist");

const args = minimist(process.argv.slice(2));

function renderGreeting(name) {
  const compiled = _.template("Hello <%= name %>!");
  return compiled({ name });
}

console.log(renderGreeting(args.name || "world"));
