import crypto from 'crypto';

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
console.log(privateKey.export({ format: 'pem', type: 'pkcs8' }));
console.log(publicKey.export({ format: 'pem', type: 'spki' }));

// or
// console.log(publicKey.export({ format: 'der', type: 'spki' }).toString('base64'));

const hmac = crypto.createHmac('sha1', 'segredo').update('algum texto').digest('hex');
console.log(hmac);

const { privateKey: rsaPrivateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
console.log(rsaPrivateKey.export({ format: 'pem', type: 'pkcs8' }));


// async rotateKeys() {
  /*
  1. push new keys at the very end of the "keys" array in your JWKS, this means the keys will become available for verification should they be encountered but not yet used for signing
  2. reload all your processes
  3. move your new key to the very front of the "keys" array in your JWKS, this means the key will be used for signing after reload
  4. reload all your processes
   */
// }
