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
        callback(msg.err ? new Error(msg.err) : null, msg.result);
    });

    child.on('error', (err: Error) => {
        console.error(err.stack);
        callback(err);
    });

    child.send(message);
}

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

async function getFakeHash(): Promise<string> {
    if (fakeHashCache) {
        return fakeHashCache;
    }
    fakeHashCache = await hash(12, Math.random().toString()); // Await here
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

    return new Promise<boolean>((resolve, reject) => {
        forkChild(message, (err, result) => {
            if (err) {
                reject(err);
            } else {
                resolve(result as boolean);
            }
        });
    });
}

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

async function hashPassword(msg: ForkMessage): Promise<string | boolean> {
    if (msg.type === 'hash') {
        const salt = await bcrypt.genSalt(Number(msg.rounds));
        const hash = await bcrypt.hash(msg.password, salt);
        return hash;
    }
    return '';
}

async function comparePasswords(msg: ForkMessage): Promise<string | boolean> {
    if (msg.type === 'compare') {
        return await bcrypt.compare(msg.password || '', msg.hash || '');
    }
    return false;
}

// child process
process.on('message', async (msg: ForkMessage) => {
    if (msg.type === 'hash') {
        try {
            const hashValue = await hashPassword(msg);
            process.send({ result: hashValue });
        } catch (err) {
            console.error(err);
            process.send({ err: (err as Error).message }); // Cast err to Error type
        } finally {
            process.disconnect();
        }
    } else if (msg.type === 'compare') {
        try {
            const compareValue = await comparePasswords(msg);
            process.send({ result: compareValue });
        } catch (err) {
            console.error(err);
            process.send({ err: (err as Error).message }); // Cast err to Error type
        } finally {
            process.disconnect();
        }
    }
});

export {};
