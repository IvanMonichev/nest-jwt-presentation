export const cookieExtractor = (
  req: { cookies: { [x: string]: null } },
  key: string
) => {
  let jwt = null

  if (req && req.cookies) {
    jwt = req.cookies[key]
  }

  return jwt
}
