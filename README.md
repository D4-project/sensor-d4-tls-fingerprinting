# sensor-d4-tls-fingerprinting
Extracts TLS certificates from pcap files or network interfaces (tcpreassembly is done thanks to gopacket), fingerprints TLS client/server interactions with ja3/ja3s and print output in JSON form.
# Use
This project is currently in its very early stage and should not be used in production.
 Check the list of issues.
## Install dependencies & go get
``` shell
$go get github.com/google/gopacket
$go get github.com/glaslos/tlsh 
$go get github.com/D4-project/sensor-d4-tls-fingerprinting
```
make allows to compile for amd64 and arm ATM.
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
