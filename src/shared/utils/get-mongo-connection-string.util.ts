interface IMongoConnectionParams {
  username: string
  password: string
  host: string
  port: string
  databaseName: string
  authDatabase: string
}

export function getMongoConnectionString({
  username,
  password,
  host,
  port,
  databaseName,
  authDatabase
}: IMongoConnectionParams): string {
  return `mongodb://${username}:${password}@${host}:${port}/${databaseName}?authSource=${authDatabase}`
}
