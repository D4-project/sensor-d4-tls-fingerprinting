arm5l: d4-tlsf.go
	env GOOS=linux GOARCH=arm GOARM=5 go build -o d4-tlsf-arm5l d4-tlsf.go
amd64l: d4-tlsf.go
	env GOOS=linux GOARCH=amd64 go build -o d4-tlsf-amd64l d4-tlsf.go
