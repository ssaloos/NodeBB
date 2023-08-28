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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
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
        callback(msg.err ? new Error(msg.err) : null, msg.result);
    });
    child.on('error', (err) => {
        console.error(err.stack);
        callback(err);
    });
    child.send(message);
}
function hash(rounds, password) {
    return __awaiter(this, void 0, void 0, function* () {
        const hashedPassword = crypto.createHash('sha512').update(password).digest('hex');
        const message = { type: 'hash', rounds, password: hashedPassword };
        return new Promise((resolve, reject) => {
            forkChild(message, (err, result) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(result);
                }
            });
        });
    });
}
exports.hash = hash;
let fakeHashCache;
function getFakeHash() {
    return __awaiter(this, void 0, void 0, function* () {
        if (fakeHashCache) {
            return fakeHashCache;
        }
        fakeHashCache = yield hash(12, Math.random().toString()); // Await here
        return fakeHashCache;
    });
}
function compare(password, hash, shaWrapped) {
    return __awaiter(this, void 0, void 0, function* () {
        const fakeHash = yield getFakeHash();
        if (shaWrapped) {
            password = crypto.createHash('sha512').update(password).digest('hex');
        }
        const message = { type: 'compare', password, hash: hash || fakeHash };
        return new Promise((resolve, reject) => {
            forkChild(message, (err, result) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(result);
                }
            });
        });
    });
}
exports.compare = compare;
// async function tryMethod<T extends string | boolean>(
//     method: (msg: ForkMessage) => Promise<T>,
//     msg: ForkMessage
// ): Promise<T> {
//     try {
//         const result = await method(msg);
//         return result;
//     } catch (err) {
//         // Handle errors if needed
//         console.error(err);
//         throw err; // Rethrow the error to propagate it
//     } finally {
//         process.disconnect();
//     }
// }
function hashPassword(msg) {
    return __awaiter(this, void 0, void 0, function* () {
        if (msg.type === 'hash') {
            const salt = yield bcrypt.genSalt(Number(msg.rounds));
            const hash = yield bcrypt.hash(msg.password, salt);
            return hash;
        }
        return '';
    });
}
function comparePasswords(msg) {
    return __awaiter(this, void 0, void 0, function* () {
        if (msg.type === 'compare') {
            return yield bcrypt.compare(msg.password || '', msg.hash || '');
        }
        return false;
    });
}
// child process
process.on('message', (msg) => __awaiter(void 0, void 0, void 0, function* () {
    if (msg.type === 'hash') {
        try {
            const hashValue = yield hashPassword(msg);
            process.send({ result: hashValue });
        }
        catch (err) {
            console.error(err);
            process.send({ err: err.message }); // Cast err to Error type
        }
        finally {
            process.disconnect();
        }
    }
    else if (msg.type === 'compare') {
        try {
            const compareValue = yield comparePasswords(msg);
            process.send({ result: compareValue });
        }
        catch (err) {
            console.error(err);
            process.send({ err: err.message }); // Cast err to Error type
        }
        finally {
            process.disconnect();
        }
    }
}));
