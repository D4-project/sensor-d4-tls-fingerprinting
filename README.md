<p align="center">
  <img alt="sensor-d4-tls-fingerprinting" src="https://raw.githubusercontent.com/D4-project/sensor-d4-tls-fingerprinting/master/media/gopherd4.png" height="140" />
  <p align="center">
    <a href="https://github.com/D4-project/sensor-d4-tls-fingerprinting/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/D4-project/sensor-d4-tls-fingerprinting/all.svg"></a>
    <a href="https://github.com/D4-project/sensor-d4-tls-fingerprinting/blob/master/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
    <a href="https://goreportcard.com/report/github.com/D4-Project/sensor-d4-tls-fingerprinting"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/D4-Project/sensor-d4-tls-fingerprinting"></a>
  </p>
</p>

**sensor-d4-tls-fingerprinting** is intended to be used to feed a D4 project client (It can be used in standalone though).

# Main features

 * extracts TLS certificates from pcap files or network interfaces
 * fingerprints TLS client/server interactions with ja3/ja3s
 * fingerprints TLS interactions with TLSH fuzzy hashing
 * write certificates in a folder
 * export in JSON to files, or stdout

# Use
This project is currently in development and is subject to change, check the list of issues.

## Compile from source
### requirements
 * git
 * golang >= 1.5
 * libpcap

``` shell
#apt install golang git libpcap-dev
```
### Go get

``` shell
$go get github.com/D4-project/sensor-d4-tls-fingerprinting
$cd $GOPATH/github.com/D4-project/sensor-d4-tls-fingerprinting
$
```
A "sensor-d4-tls-fingerprinting" compiled for your architecture should then be in $GOPATH/bin
Alternatively, use make to compile arm/linux or amd64/linux

## How to use

Read from pcap:
``` shell
$ ./d4-tlsf-amd64l -r=file 

```
Read from interface (promiscious mode):
``` shell
$ ./d4-tlsf-amd64l -i=interface 

```
Write x509 certificates to folder:
``` shell
$ ./d4-tlsf-amd64l -w=folderName 
```
Write output json inside folder

``` shell
$ ./d4-tlsf-amd64l -j=folderName 
```
