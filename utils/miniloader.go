package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	pemData, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalln(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatalln("could not pem decode")
	}

	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalln(err)
	}
}
