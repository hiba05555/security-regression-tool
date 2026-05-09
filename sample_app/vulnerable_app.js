/**
 * Sample vulnerable JavaScript/Node.js application
 * This file intentionally contains security vulnerabilities for testing.
 */

const express = require('express');
const mysql = require('mysql');

// VULNERABILITY 1: Hardcoded credentials
const DB_PASSWORD = "root123";
const API_SECRET = "hardcoded-secret-key-12345";

// VULNERABILITY 2: SQL Injection
function getUser(username) {
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    db.query(query, (err, results) => {
        return results;
    });
}

// VULNERABILITY 3: XSS - No output encoding
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<h1>Results for: ${query}</h1>`); // Dangerous: no sanitization
});

// VULNERABILITY 4: Command Injection
const { exec } = require('child_process');
function pingHost(host) {
    exec(`ping -c 1 ${host}`, (error, stdout) => { // Dangerous
        return stdout;
    });
}

// VULNERABILITY 5: Insecure random token
function generateToken() {
    return Math.random().toString(36); // Dangerous: not cryptographically secure
}

// VULNERABILITY 6: eval() usage
function calculate(expression) {
    return eval(expression); // Extremely dangerous
}

// VULNERABILITY 7: Prototype pollution
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key]; // Dangerous: no hasOwnProperty check
    }
}

// VULNERABILITY 8: Path Traversal
const fs = require('fs');
app.get('/file', (req, res) => {
    const file = req.query.name;
    res.sendFile('/var/www/' + file); // Dangerous: no path validation
});
