import { IHasher } from '../types/hasher.interface'
import { Inject } from '@nestjs/common'
import { compare, genSalt, hash } from 'bcrypt'

export class BcryptHasher implements IHasher {
  constructor(@Inject('SaltRound') private readonly saltRounds: number) {}

  compareHash(data: string, encrypted: string): Promise<boolean> {
    return compare(data, encrypted)
  }

  async hash(value: string): Promise<string> {
    const salt = await genSalt(this.saltRounds)
    return await hash(value, salt)
  }
}
