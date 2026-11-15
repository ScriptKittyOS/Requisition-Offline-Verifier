// Runs a cases file through the Go standard library's crypto/mldsa (ML-DSA-87, pure, external interface).
// usage: go run . CASES.tsv
// Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
package main

import (
	"bufio"
	"crypto/mldsa"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func unhex(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func verify(pk, sig, msg, ctx []byte) bool {
	key, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pk)
	if err != nil {
		return false
	}
	return mldsa.Verify(key, msg, sig, &mldsa.Options{Context: string(ctx)}) == nil
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	n, wrong := 0, []string{}
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) != 6 {
			os.Exit(2)
		}
		got := verify(unhex(p[1]), unhex(p[2]), unhex(p[3]), unhex(p[4]))
		n++
		if got != (p[5] == "1") {
			wrong = append(wrong, p[0])
		}
	}
	fmt.Printf("Go crypto/mldsa (%s): %d cases, %d disagree with the expected result %v\n", runtime.Version(), n, len(wrong), wrong)
	if len(wrong) > 0 {
		os.Exit(1)
	}
}
