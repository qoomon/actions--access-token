
// eslint-disable-next-line @typescript-eslint/no-explicit-any
console.log('##### ', (new globalThis.Request('https://example.com') as any ).duplex)
