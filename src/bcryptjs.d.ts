declare module 'bcryptjs' {
    interface BcryptStatic {
        genSalt(rounds: number): Promise<string>;
        hash(data: string | Buffer, saltOrRounds: string | number): Promise<string>;
        compare(data: string | Buffer, encrypted: string): Promise<boolean>;
    }

    const bcrypt: BcryptStatic;
    export = bcrypt;
}
