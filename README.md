# sensor-d4-tls-fingerprinting
Extracts TLS certificates from pcap files or network interfaces, fingerprints TLS client/server interactions with ja3/ja3s.
# Use
This project is currently in its very early stage and relies mainly on a customized version of ![gopacket](http://github.com/google/gopacket "gopacket link") that will be the subject of a pull request later on.
## Install dependencies & go get
``` shell
$go get github.com/gallypette/gopacket
$go get github.com/google/gopacket
$cd $GOPATH/src/github.com/google/gopacket
$git remote add fork github.com/gallypette/gopacket
$go get github.com/D4-project/sensor-d4-tls-fingerprinting
```
## How to use
This early version takes a pcap file in input with the "-r" flag, and outputs the valid x509 certificates it found in current folder.
It speaks networks too with "-i".
