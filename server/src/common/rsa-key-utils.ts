/**
 * This function will format a single line pem key to a well formatted pem key
 * @param keyString - pem key string
 * @return well formatted pem key
 */
export function formatPEMKey(keyString: string): string {
  keyString = keyString.trim(); // remove leading and trailing whitespace
  const header = keyString.match(/^-----BEGIN [\w\s]+ KEY-----/g)?.[0];
  const footer = keyString.match(/-----END [\w\s]+ KEY-----$/g)?.[0];
  if (!header || !footer) throw Error('Invalid key format');

  const key = keyString
      .slice(header.length, -footer.length) // remove header and footer
      .replace(/\s+/g, ''); // remove all whitespace

  // format key
  return '' +
      header + '\n' +
      // split key into 64 character lines,
      key.replace(/.{1,64}/g, '$&\n') +
      footer + '\n'
}
