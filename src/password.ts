import * as path from 'path';
import * as crypto from 'crypto';
import * as bcrypt from 'bcryptjs';
import { fork, ChildProcess } from 'child_process';

interface HashMessage {
    type: 'hash';
    rounds: number;
    password: string;
}

interface CompareMessage {
    type: 'compare';
    password: string;
    hash: string;
}

type ForkMessage = HashMessage | CompareMessage;

function forkChild(
    message: ForkMessage,
    callback: (err: Error | null, result?: string | boolean) => void
) {
    const child: ChildProcess = fork(path.join(__dirname, 'password'));

    child.on('message', (msg: { err?: string; result: string | boolean }) => {
        const { err, result } = msg; // Use object destructuring
        const error = err ? new Error(err) : null;
        callback(error, result);
    });

    child.on('error', (err: Error) => {
        console.error(err.stack);
        callback(err, undefined);
    });

    child.send(message);
}

// Hashing and comparison functions...
export async function hash(rounds: number, password: string): Promise<string> {
    const hashedPassword = crypto.createHash('sha512').update(password).digest('hex');
    const message: HashMessage = { type: 'hash', rounds, password: hashedPassword };

    return new Promise<string>((resolve, reject) => {
        forkChild(message, (err, result) => {
            if (err) {
                reject(err);
            } else {
                resolve(result as string);
            }
        });
    });
}

let fakeHashCache: string | undefined;
let fakeHashPromise: Promise<string> | null = null; // Track the fake hash promise

async function getFakeHash(): Promise<string> {
    if (fakeHashCache) {
        return fakeHashCache;
    }

    if (fakeHashPromise === null) {
        fakeHashPromise = hash(12, Math.random().toString());
    }

    const resolvedFakeHashPromise = await fakeHashPromise;
    fakeHashCache = resolvedFakeHashPromise;
    fakeHashPromise = null; // Reset the fake hash promise
    return fakeHashCache;
}

export async function compare(
    password: string,
    hash: string,
    shaWrapped: boolean
): Promise<boolean> {
    const fakeHash = await getFakeHash();

    if (shaWrapped) {
        password = crypto.createHash('sha512').update(password).digest('hex');
    }

    const message: CompareMessage = { type: 'compare', password, hash: hash || fakeHash };

    try {
        const result = await new Promise<boolean>((resolve, reject) => {
            forkChild(message, (err, result) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(result as boolean);
                }
            });
        });

        return result;
    } catch (error) {
        console.error(error);
        throw error;
    }
}

async function hashPassword(msg: HashMessage): Promise<string> {
    const salt = await bcrypt.genSalt(msg.rounds);
    const hash = await bcrypt.hash(msg.password, salt);
    return hash;
}

async function comparePasswords(msg: CompareMessage): Promise<boolean> {
    return await bcrypt.compare(msg.password || '', msg.hash || '');
}

function sendResult(result: string | boolean | undefined) {
    if (result !== undefined) {
        process.send({ result });
    }
}

function sendError(error: Error) {
    process.send({ err: error.message });
}

async function handleAsyncOperation(msg: ForkMessage) {
    try {
        let result: string | boolean | undefined;

        if (msg.type === 'hash') {
            result = await hashPassword(msg);
        } else if (msg.type === 'compare') {
            result = await comparePasswords(msg);
        }

        sendResult(result);
    } catch (err) {
        console.error(err);
        sendError(err as Error);
    } finally {
        setImmediate(() => {
            process.disconnect();
        });
    }
}

process.on('message', (msg: ForkMessage) => {
    handleAsyncOperation(msg).catch((err) => {
        console.error(err);
    });
});

export {};
