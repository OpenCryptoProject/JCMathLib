# Security Policy

## Supported Versions

JCMathLib is experimental software by nature. Its primary purpose is to let developers openly release functional JavaCard applets without being restricted by the licensing of proprietary packages (even if their production applications rely on those packages).

Therefore, we do not commit to long-term support for any specific version of the library. Only the latest release is maintained. JCMathLib is **not** recommended for use in production environments as is, because we cannot guarantee its security properties on arbitrary underlying smartcard platforms.

For example, many of the library's methods are known to leak information through timing side channels. While constant-time re-implementations of some of them exist in the repository, they tend to be significantly slower, which conflicts with the library's primary purpose of enabling open-source applet releases.

## Reporting a Vulnerability

Although the library focuses primarily on functionality and is not intended to be a production component, we are interested in any bugs and vulnerabilities you find. If you find a problem, please open an issue describing it. If you believe the vulnerability is critical (e.g., it allows practical extraction of a private key), please contact us privately by email, optionally encrypted with our [PGP key](https://crocs.fi.muni.cz/people/svenda/pgp).
