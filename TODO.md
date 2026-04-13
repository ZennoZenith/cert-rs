# TODO

- webpki-roots = "0.26" # If you need to verify ACME server certs with webpki roots
- Generation privte key shoudl be delegate to other crates
- Check if std::time::Duration is possible instead of chrono
- Profiles Meta: Is defined in later rfc
- tracing support
- [Your client should offer a runtime option to specify a list of trusted root CAs.](https://github.com/letsencrypt/pebble?tab=readme-ov-file#avoiding-client-https-errors)
- Error object with subproblems [6.7.1. Subproblems]
- Order List [RFC 8555 §7.1.2.1](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2.1)
- [7.4.1. Pre-authorization]
- [7.6. Certificate Revocation]
- [6.6. Rate Limits]
- [6.7. Errors]
