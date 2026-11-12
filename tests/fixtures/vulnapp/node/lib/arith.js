"use strict";

const TOKEN = /\s*(\d+(?:\.\d+)?|[-+*/()])\s*/y;

function tokenize(text) {
  const tokens = [];
  TOKEN.lastIndex = 0;
  while (TOKEN.lastIndex < text.length) {
    const match = TOKEN.exec(text);
    if (!match) {
      throw new Error("invalid expression");
    }
    tokens.push(match[1]);
  }
  return tokens;
}

function evaluateArithmetic(text) {
  const tokens = tokenize(text);
  let pos = 0;

  function factor() {
    const token = tokens[pos++];
    if (token === "(") {
      const value = sum();
      if (tokens[pos++] !== ")") {
        throw new Error("invalid expression");
      }
      return value;
    }
    if (token === "-") {
      return -factor();
    }
    const value = Number(token);
    if (Number.isNaN(value)) {
      throw new Error("invalid expression");
    }
    return value;
  }

  function product() {
    let value = factor();
    while (tokens[pos] === "*" || tokens[pos] === "/") {
      value = tokens[pos++] === "*" ? value * factor() : value / factor();
    }
    return value;
  }

  function sum() {
    let value = product();
    while (tokens[pos] === "+" || tokens[pos] === "-") {
      value = tokens[pos++] === "+" ? value + product() : value - product();
    }
    return value;
  }

  const result = sum();
  if (pos !== tokens.length) {
    throw new Error("invalid expression");
  }
  return result;
}

module.exports = { evaluateArithmetic };
