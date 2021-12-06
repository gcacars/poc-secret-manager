import { createECDH, createPrivateKey, createPublicKey } from 'crypto';
import { fromKeyLike } from 'jose-node-esm-runtime/jwk/from_key_like';

async function main() {
  //const pem = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOIkZLYEw6DyNfvhjF3hWNUY2puGyEb0YKE7PVnaxfkN\n----- END PRIVATE KEY-----';
  const pem = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOIkZLYEw6DyNfvhjF3hWNUY2puGyEb0YKE7PVnaxfkN
-----END PRIVATE KEY-----`;

  const publicKey = createPublicKey(pem);
  const privateKey = createPrivateKey(pem);

  const privateJwk = await fromKeyLike(privateKey);
  const publicJwk = await fromKeyLike(publicKey);

  console.log(privateJwk, publicJwk);
}

main();
