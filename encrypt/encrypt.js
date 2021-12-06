import { generateKeyPairSync } from 'crypto';
import { CompactEncrypt } from 'jose-node-esm-runtime/jwe/compact/encrypt';
import { EncryptJWT } from 'jose-node-esm-runtime/jwt/encrypt';
import { jwtDecrypt } from 'jose-node-esm-runtime/jwt/decrypt';
import { compactDecrypt } from 'jose-node-esm-runtime/jwe/compact/decrypt'
import { fromKeyLike } from 'jose-node-esm-runtime/jwk/from_key_like';

const start = Date.now();
let step = start;

const encoder = TextEncoder.prototype.encode.bind(new TextEncoder());
const { publicKey, privateKey } = generateKeyPairSync('x25519');

console.info('Keys generated');
console.info(`== Elapsed ${Date.now() - step}ms`);
step = Date.now();

console.log(privateKey.export({ format: 'pem', type: 'pkcs8' }));
console.info(`== Elapsed ${Date.now() - step}ms`);
step = Date.now();
console.log();


const publicJwk = await fromKeyLike(publicKey);
console.log(publicJwk);
console.log(await fromKeyLike(privateKey));
console.info(`== Elapsed ${Date.now() - step}ms`);
step = Date.now();
console.log();

const issuer = 'https://idp.nexso.dev';
const content = {
  aud: 'https://module.nexso.dev',
  iat: Date.now(),
  exp: Date.now() + 5 * 60 * 1000,
  // nbf: Date.now() - 1000,
  sub: 'user@nx',
  iss: issuer,
};

async function main() {
  console.info(`== Call main ${Date.now() - step}ms`);
  step = Date.now();
  
  // JWT
  const jwt = await new EncryptJWT(content)
    .setProtectedHeader({
      alg: 'ECDH-ES+A128KW',
      enc: 'A128GCM',
      kid: 'v1',
      sid: 'nexso',
      aud: 'https://module.nexso.dev',
    })
    /*.setIssuedAt()
    .setIssuer(issuer)
    .setAudience(content.aud)
    .setExpirationTime('20m')*/
    .encrypt(publicKey);

  console.info('JWT Encrypted token:');
  console.log(jwt);
  console.info(`== Elapsed ${Date.now() - step}ms`);
  step = Date.now();
  console.info('\n');

  // Encrypt
  const serializedContent = JSON.stringify(content);
  const token = await new CompactEncrypt(encoder(serializedContent))
    .setProtectedHeader({
      alg: 'ECDH-ES+A128KW',
      enc: 'A128GCM',
      kid: 'v1',
      sid: 'nexso',
      aud: 'https://module.nexso.dev',
    })
    .encrypt(publicKey);
  
  console.info('Encrypted token:');
  console.log(token);
  console.info(`== Elapsed ${Date.now() - step}ms`);
  step = Date.now();
  console.info('\n');

  // Decrypt JWT
  const { payload, protectedHeader } = await jwtDecrypt(jwt, privateKey, {
    issuer,
    audience: content.aud,
  });

  console.info('Decrypted JWT token:');
  console.log({ payload, protectedHeader });
  console.info(`== Elapsed ${Date.now() - step}ms`);
  step = Date.now();
  console.info('\n');

  // Decrypt
  const decoder = new TextDecoder();
  const { plaintext, protectedHeader: jweHeader } = await compactDecrypt(token, privateKey);
  const jweContent = JSON.parse(decoder.decode(plaintext));
  console.log({ payload: jweContent, jweHeader });
  console.info(`== Elapsed ${Date.now() - step}ms`);

  console.info(`==== Total Elapsed Time: ${Date.now() - start}ms`);
}

main();
