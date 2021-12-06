import rsaPemToJwk from 'rsa-pem-to-jwk';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

import { createPrivateKey, createPublicKey } from 'crypto';
import { fromKeyLike } from 'jose-node-esm-runtime/jwk/from_key_like';

async function main() {
  console.time('secret');
  const client = new SecretManagerServiceClient({ keyFilename: 'nx-core-6c70d13bf6ca.json' });
  const [ accessResponse ] = await client.accessSecretVersion({
    name: 'projects/1037115734293/secrets/poc-auth-key/versions/1',
  });

  const responsePayload = accessResponse.payload.data.toString('utf8');
  console.info(responsePayload);
  console.timeEnd('secret');
  console.log('');
  
  // EdDSA
  console.time('jwk');
  const publicKey = createPublicKey(responsePayload);
  const privateKey = createPrivateKey(responsePayload);

  const privateJwk = await fromKeyLike(privateKey);
  const publicJwk = await fromKeyLike(publicKey);

  console.log(privateJwk, publicJwk);
  console.timeEnd('jwk');

  // mount jwks
  const test = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDfn1nKQshOSj8xw44oC2klFWSNLmK3BnHONCJ1bZfq0EQ5gIfg
tlvB+Px8Ya+VS3OnK7Cdi4iU1fxO9ktN6c6TjmmmFevk8wIwqLthmCSF3r+3+h4e
ddj7hucMsXWv05QUrCPoL6YUUz7Cgpz7ra24rpAmK5z7lsV+f3BEvXkrUQIDAQAB
AoGAC0G3QGI6OQ6tvbCNYGCqq043YI/8MiBl7C5dqbGZmx1ewdJBhMNJPStuckhs
kURaDwk4+8VBW9SlvcfSJJrnZhgFMjOYSSsBtPGBIMIdM5eSKbenCCjO8Tg0BUh/
xa3CHST1W4RQ5rFXadZ9AeNtaGcWj2acmXNO3DVETXAX3x0CQQD13LrBTEDR44ei
lQ/4TlCMPO5bytd1pAxHnrqgMnWovSIPSShAAH1feFugH7ZGu7RoBO7pYNb6N3ia
C1idc7yjAkEA6Nfc6c8meTRkVRAHCF24LB5GLfsjoMB0tOeEO9w9Ous1a4o+D24b
AePMUImAp3woFoNDRfWtlNktOqLel5PjewJBAN9kBoA5o6/Rl9zeqdsIdWFmv4DB
5lEqlEnC7HlAP+3oo3jWFO9KQqArQL1V8w2D4aCd0uJULiC9pCP7aTHvBhcCQQDb
W0mOp436T6ZaELBfbFNulNLOzLLi5YzNRPLppfG1SRNZjbIrvTIKVL4N/YxLvQbT
NrQw+2OdQACBJiEHsdZzAkBcsTk7frTH4yGx0VfHxXDPjfTj4wmD6gZIlcIr9lZg
4H8UZcVFN95vEKxJiLRjAmj6g273pu9kK4ymXNEjWWJn
-----END RSA PRIVATE KEY-----
`;
  const jwkRSA = rsaPemToJwk(test, {
    use: 'sig',
    kid: 'teste',
  }, 'public');
  console.log('========== RSA ==========');
  console.log(jwkRSA);
}

main();
