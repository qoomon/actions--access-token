import {DecodedJwt} from 'fast-jwt'
import buildJwks, {GetJwksOptions} from 'get-jwks'

/**
 * This function will create a function to fetch the public key for the given decoded jwt
 * @param options - jwks options
 * @returns function to fetch the public key
 */
export function buildJwksKeyFetcher(options: GetJwksOptions): (jwt: DecodedJwt) => Promise<string> {
  const jwks = buildJwks(options)
  return async ({header, payload}) => await jwks.getPublicKey({
    kid: header.kid,
    alg: header.alg,
    domain: payload.iss,
  })
}
