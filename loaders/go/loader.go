package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func main() {
	var buffer bytes.Buffer

	if _, err := io.Copy(&buffer, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	block, _ := pem.Decode(buffer.Bytes())
	if block == nil {
		fmt.Fprintln(os.Stderr, "could not pem decode")
		os.Exit(1)
	}

	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
