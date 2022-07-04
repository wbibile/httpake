

HttPake 
=======

HttPake is a prototype HTTP authentication scheme to use Password Authenticated Key Exchange (PAKE) to authenticate users.  The current implementation uses raw Diffie-Hellman, due to weakness in security this will be cahenged to use a more secure PAKE protocol such as SRP (Secure Remote Password),


Features
----------

* HTTP authentication scheme based on PAKE (Password Authenticated Key Exchange)
* Built on top of reliable cryptographic techniques 
    * DHE (Diffie-Hellman key Exchange)
    * HMAC_SHA256 subject signatures 
    * 256-bit KDF (Key Derivation Function) based on HMAC_SHA256
* Possibility of extending to use AES encryption, with a suitable block cipher mode of operation such as CBC.
* Client/server mutual authentication  
    * This improves resilience against phishing attacks as, both parties must know the password
* Password is never sent over the wire (not even a hash of the password)
    * Improved resistance to static brute-force/dictionary attacks 
    * Minimizes the danger of using relatively simple passwords
* Secure HTTP session, request and, response identifiers 

Project structure
-----------------
This project contains the following top-level directories.

httpake:
Java Eclipse project consisting of general purpose HttPake utilities.

httpake-client:
Java Eclipse, HttPake client project. The client is implemented as a wrapper around the Apache HTTP client.

httpake-server:
Java Eclipse, HttPake setvlet filter project. This is a HTTP servlet filter that implements the rules for HttPake authentication and, forwards authenticated requests down the filter chain.

test:
Java Eclipse project containing system tests. These are end-to-end system  tests that utilises live client server interactions (binds to 127.0.0.1:8888).

lib: 
Parent directory for sub-directories containing libraries (JAR files).

lib/shared: 
Contains shared libraries used by all projects.

lib/client:
Contains libraries used exclusively by the httpake-client project

lib/server:
Contains libraries used exclusively the httpake-server project 

lib/test:
Contains libraries used exclusively by the “test” project 
