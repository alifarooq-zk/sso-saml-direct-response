# IdP-initiated SSO SAML 2.0

## Scripts

- `npm run start` - start an Identity Provider.

## Key generation

```
openssl genrsa -out private_key.pem 4096
openssl req -new -x509 -key private_key.pem -out public_cert.cer -days 3650
```
