HttPake Cononical repository
============================

HttPake is a HTTP authentication scheme, it is pronounced "HTTP pack". This repository contains multiple Java projects 
with an example HTTP client and, a servlet filter for handling HttPake autrhentication.


Features
--------
Headline features of HttPake are

* Brings PAKE (Password Authenticated Key Exchange) to HTTP 
* HttPake is built on top of Diffie-Hellmen HMAC_SHA256
* Possibility of extending to use AES-CBC encryption
* Allowing clients and servers to mutually authenticate each other 
* Password is never sent over the wire (not even a hash of the password)
* Resistant to brute force attacks on captured data
* Resistant to dictionary attacks based on captured data, users are free to choose relatively simple passwords

Project structure
-----------------

This project contains the following toplevel foleder.

httpake:
Java Eclipse project consisting of general purpose HttPake utilities.

httpake-client:
Java Eclipse, HttPake client project. The client is implemented wrapper around the Apache HTTP client.

httpake-server:
Java Eclipse, HttPake setvlet filter project. This is a HTTP servlet filter that implements the rules for HttPake authentication and, forwards authenticated requests down the filter chain.

test:
Java Exclipse project containing system tests. These are end-to-end system  tests that utilises live client server interactions.

lib: 
Contains libraries (JAR fils) that the above projects depend on

lib/shared: 
Libraries utlized by all Java projects 

lib/client:
Libraries for the hpake-examples-client project

lib/server:
Libraries for the hpake-examples-server project 

lib/test:
Libraries for the test project 
