export interface IHasher {
  hash(value: string): Promise<string>
  compareHash(data: string, encrypted: string): Promise<boolean>
}
