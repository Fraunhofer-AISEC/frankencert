# Frankencert - Adversarial Testing of Certificate Validation in SSL/TLS Implementations

## What are frankencerts?

Frankencerts are specially crafted SSL certificates for testing certificate validation code in SSL/TLS implementations.
The technique is described in detail in the 2014 IEEE Symposium on Security and Privacy (Oakland) paper - *Using Frankencerts for Automated Adversarial Testing of Certificate Validation in SSL/TLS Implementations* by Chad Brubaker, Suman Jana, Baishakhi Ray, Sarfraz Khurshid, and Vitaly Shmatikov.


## Why is frankencert generator useful?

Frankencert generator is essentially a smart fuzzer for testing SSL/TLS certificate validation code.
If you are a developer who is implementing any sort of SSL/TLS certificate validation code (either as part of an SSL/TLS library or an application), you can use the frankencert generator to auto-generate different test certificates involving complex corner cases.

We have successfully used frankencerts to find serious vulnerabilities in GnuTLS, PolarSSL, CyaSSL, and MatrixSSL as described in our Oakland 2014 paper.
We also found several discrepancies between how different SSL/TLS implementations report errors back to the user.
For example, when presented with an expired, self-signed certificate, NSS, Chrome on Linux, and Safari report that the certificate has expired but not that the issuer is invalid.


## How do frankencerts work?

The basic idea of frankencerts is to take a bunch of certificates as seeds and use random mutations on different fields and extensions to create new test certificates (frankencerts).
Using frankencerts as server-side inputs into an SSL/TLS handshake can help systematically test correctness of the certificate validation code.
