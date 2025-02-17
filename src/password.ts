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
        const { err, result } = msg;
        const error = err ? new Error(err) : null;
        callback(error, result);
    });

    child.on('error', (err: Error) => {
        console.error(err.stack);
        callback(err, undefined);
    });

    child.send(message);
}

async function forkChildAsync(message: ForkMessage): Promise<string> {
    return new Promise<string>((resolve, reject) => {
        const child: ChildProcess = fork(path.join(__dirname, 'password'));

        child.on('message', (msg: { err?: string; result: string }) => {
            const { err, result } = msg;
            if (err) {
                reject(new Error(err));
            } else {
                resolve(result);
            }
        });

        child.on('error', (err: Error) => {
            console.error(err.stack);
            reject(err);
        });

        child.send(message);
    });
}

export async function hash(rounds: number, password: string): Promise<string> {
    const hashedPassword = crypto.createHash('sha512').update(password).digest('hex');
    return await forkChildAsync({ type: 'hash', rounds: rounds, password: hashedPassword });
}

let fakeHashCache: string | undefined;
let fakeHashPromise: Promise<string> | null = null;

async function getFakeHash(): Promise<string> {
    if (fakeHashCache) {
        return fakeHashCache;
    }

    if (fakeHashPromise === null) {
        try {
            fakeHashPromise = hash(12, Math.random().toString());
            const resolvedFakeHashPromise = await fakeHashPromise;
            fakeHashCache = resolvedFakeHashPromise;
            fakeHashPromise = null;
            return fakeHashCache;
        } catch (error) {
            console.error(error);
            throw error;
        }
    }
    return fakeHashCache;
}

export async function compare(
    password: string,
    hash: string,
    shaWrapped: boolean
): Promise<boolean> {
    try {
        const fakeHash = await getFakeHash();

        if (shaWrapped) {
            password = crypto.createHash('sha512').update(password).digest('hex');
        }

        const message: CompareMessage = { type: 'compare', password, hash: hash || fakeHash };

        return new Promise<boolean>((resolve, reject) => {
            forkChild(message, (err, result) => {
                if (err) {
                    console.error(err);
                    reject(err);
                } else {
                    resolve(result as boolean);
                }
            });
        });
    } catch (error) {
        console.error(error);
        throw error;
    }
}

async function hashPassword(msg: HashMessage): Promise<string> {
    const salt = await bcrypt.genSalt(parseInt(msg.rounds.toString(), 10));
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

async function tryMethod<T>(method: (msg: ForkMessage) => Promise<T>, msg: ForkMessage): Promise<T> {
    try {
        return await method(msg);
    } catch (err) {
        console.error(err);
        throw err;
    }
}

async function handleAsyncOperation(msg: ForkMessage) {
    try {
        if (msg.type === 'hash') {
            const result = await tryMethod(hashPassword, msg);
            sendResult(result);
        } else if (msg.type === 'compare') {
            const result = await tryMethod(comparePasswords, msg);
            sendResult(result);
        }
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

