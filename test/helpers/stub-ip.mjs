// Loaded with `node --import` into a spawned CLI: answers the public-IP lookup locally, so a test
// can run `daypass open` with the network step against the fake EC2 and nothing leaves the machine.
const real = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url).startsWith('https://checkip.amazonaws.com')) return new Response('203.0.113.7\n');
  return real(url, init);
};
