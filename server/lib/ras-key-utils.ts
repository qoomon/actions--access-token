/**
 * This function will format a single line pem key to a well formatted pem key
 * @param keyString - pem key string
 * @returns well formatted pem key
 */
export function formatPEMKey(keyString: string): string {
  const headerMatch = keyString.match(/^\s*-----BEGIN [\w\d\s]+ KEY-----/g)
  const footerMatch = keyString.match(/-----END [\w\d\s]+ KEY-----\s*$/g)
  if (!headerMatch || !footerMatch) throw Error('Invalid key format')

  const key = keyString
      .slice(headerMatch[0].length)
      .slice(0, -footerMatch[0].length)
      .replace(/\s+/g, '')

  return headerMatch[0] + '\n' +
      key.replace(/.{1,64}/g, '$&\n') +
      footerMatch[0] + '\n'
}
