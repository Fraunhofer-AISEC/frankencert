package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		file := scanner.Text()
		pemData, err := os.ReadFile(file)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			fmt.Println("could not pem decode")
			os.Exit(1)
		}

		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("%s: %s\n", file, err)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
