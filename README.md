### SPID SAML Library for Go

- Customized from [spid-go](https://github.com/italia/spid-go) library.

#### Usage (Example)
- create idp_depo directory
- download idp metadata under the idp_depo
- create certs under certs directory
- `openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -sha256 -days 3650 -nodes -subj "/CN=localhost"`
- set other keys in sp.toml
- serve with Echo framework
