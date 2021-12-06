# POC Secret Manager

## Gerar EcDSA

Generate private key:

```cli
openssl genpkey -algorithm Ed25519 -out auth-key.pem
```

Get the public one:

```cli
openssl pkey -in auth-key.pem -pubout
```
