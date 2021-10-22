package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func processCert(input <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for in := range input {
		parts := strings.SplitN(in, ",", 2)
		if len(parts) != 2 {
			continue
		}

		var (
			shasum = parts[0]
			cert   = parts[1]
		)
		certRaw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certRaw,
		}

		var buf bytes.Buffer
		if err := pem.Encode(&buf, block); err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}

		p := filepath.Join("certs", fmt.Sprintf("%s.pem", shasum))
		if err := os.WriteFile(p, buf.Bytes(), 0644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
	}
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	if err := os.Mkdir("certs", 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var (
		wg sync.WaitGroup
		in = make(chan string, 16)
	)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go processCert(in, &wg)
	}
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			} else {
				break
			}
		}

		in <- string(line)
	}

	close(in)
	wg.Wait()
}
