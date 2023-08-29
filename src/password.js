"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.compare = exports.hash = void 0;
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const bcrypt = __importStar(require("bcryptjs"));
const child_process_1 = require("child_process");
function forkChild(message, callback) {
    const child = (0, child_process_1.fork)(path.join(__dirname, 'password'));
    child.on('message', (msg) => {
        const { err, result } = msg;
        const error = err ? new Error(err) : null;
        callback(error, result);
    });
    child.on('error', (err) => {
        console.error(err.stack);
        callback(err, undefined);
    });
    child.send(message);
}
async function forkChildAsync(message) {
    return new Promise((resolve, reject) => {
        const child = (0, child_process_1.fork)(path.join(__dirname, 'password'));
        child.on('message', (msg) => {
            const { err, result } = msg;
            if (err) {
                reject(new Error(err));
            }
            else {
                resolve(result);
            }
        });
        child.on('error', (err) => {
            console.error(err.stack);
            reject(err);
        });
        child.send(message);
    });
}
async function hash(rounds, password) {
    const hashedPassword = crypto.createHash('sha512').update(password).digest('hex');
    const message = { type: 'hash', rounds, password: hashedPassword };
    return await forkChildAsync(message);
}
exports.hash = hash;
let fakeHashCache;
let fakeHashPromise = null;
async function getFakeHash() {
    if (fakeHashCache) {
        return fakeHashCache;
    }
    if (fakeHashPromise === null) {
        fakeHashPromise = hash(12, Math.random().toString());
    }
    const resolvedFakeHashPromise = await fakeHashPromise;
    fakeHashCache = resolvedFakeHashPromise;
    fakeHashPromise = null;
    return fakeHashCache;
}
async function compare(password, hash, shaWrapped) {
    const fakeHash = await getFakeHash();
    if (shaWrapped) {
        password = crypto.createHash('sha512').update(password).digest('hex');
    }
    const message = { type: 'compare', password, hash: hash || fakeHash };
    return new Promise((resolve, reject) => {
        forkChild(message, (err, result) => {
            if (err) {
                console.error(err);
                reject(err);
            }
            else {
                resolve(result);
            }
        });
    });
}
exports.compare = compare;
async function hashPassword(msg) {
    const salt = await bcrypt.genSalt(msg.rounds);
    const hash = await bcrypt.hash(msg.password, salt);
    return hash;
}
async function comparePasswords(msg) {
    return await bcrypt.compare(msg.password || '', msg.hash || '');
}
function sendResult(result) {
    if (result !== undefined) {
        process.send({ result });
    }
}
function sendError(error) {
    process.send({ err: error.message });
}
async function handleAsyncOperation(msg) {
    try {
        let result;
        if (msg.type === 'hash') {
            result = await hashPassword(msg);
        }
        else if (msg.type === 'compare') {
            result = await comparePasswords(msg);
        }
        sendResult(result);
    }
    catch (err) {
        console.error(err);
        sendError(err);
    }
    finally {
        setImmediate(() => {
            process.disconnect();
        });
    }
}
process.on('message', (msg) => {
    handleAsyncOperation(msg).catch((err) => {
        console.error(err);
    });
});
