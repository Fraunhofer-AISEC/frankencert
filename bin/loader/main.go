package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	files, err := os.ReadDir(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	logFile, err := os.Create("goLoad-fails.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	for _, f := range files {
		path := filepath.Join(os.Args[1], f.Name())
		pemData, err := os.ReadFile(path)
		if err != nil {
			log.Printf("could not open '%s': %s", path, err)
			continue
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			log.Printf("could not decode '%s'", f)
			continue
		}

		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			logFile.WriteString(fmt.Sprintln(path))
			continue
		}
	}
}
