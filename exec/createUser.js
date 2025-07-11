const readline = require('readline');
const { db } = require('../handlers/db.js');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const CatLoggr = require('cat-loggr');
const log = new CatLoggr();
const saltRounds = process.env.SALT_ROUNDS || 10;

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function doesUserExist(username) {
    const users = await db.get('users');
    if (users) {
        return users.some(user => user.username === username);
    } else {
        return false;
    }
}

async function doesEmailExist(email) {
    const users = await db.get('users');
    if (users) {
        return users.some(user => user.email === email);
    } else {
        return false;
    }
}

async function initializeUsersTable(username, email, password) {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userId = uuidv4();
    const users = [{ userId, username, email, password: hashedPassword, accessTo: [], admin: true, verified: true }];
    return db.set('users', users);
}

async function addUserToUsersTable(username, email, password) {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userId = uuidv4();
    const users = await db.get('users') || [];
    users.push({ userId, username, email, password: hashedPassword, accessTo: [], admin: true, verified: true });
    return db.set('users', users);
}

async function createUser(username, email, password) {
    const users = await db.get('users');
    if (!users) {
        return initializeUsersTable(username, email, password);
    } else {
        return addUserToUsersTable(username, email, password);
    }
}

function askQuestion(question) {
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            resolve(answer);
        });
    });
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

async function main() {
    const args = process.argv.slice(2);
    const flags = {};
    args.forEach(arg => {
        const [key, value] = arg.split('=');
        if (key.startsWith('--')) {
            flags[key.slice(2)] = value;
        }
    });

    const username = flags.username || await askQuestion("Username: ");
    const email = flags.email || await askQuestion("Email: ");

    if (!isValidEmail(email)) {
        log.error("Invalid email!");
        if (!flags.email) return main(); // Retry if no email flag is passed
    }

    const password = flags.password || await askQuestion("Password: ");

    const userExists = await doesUserExist(username);
    const emailExists = await doesEmailExist(email);
    if (userExists || emailExists) {
        log.error("User already exists!");
        if (!flags.username || !flags.email) return main(); // Retry if no flags are passed
    }

    try {
        await createUser(username, email, password);
        log.info("Done! User created.");
        rl.close();
    } catch (err) {
        log.error('Error creating user:', err);
        rl.close();
    }
}

main().catch(err => {
    console.error('Unexpected error:', err);
    rl.close();
});
