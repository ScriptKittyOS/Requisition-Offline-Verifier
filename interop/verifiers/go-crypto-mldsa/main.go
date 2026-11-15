// Runs a cases file through the Go standard library's crypto/mldsa (ML-DSA-87, pure, external interface).
// usage: go run . CASES.tsv
// Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
package main

import (
	"bufio"
	"bytes"
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
	if err != nil || len(b) == 0 {
		fmt.Fprintln(os.Stderr, "bad hex")
		os.Exit(2)
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
		fmt.Fprintln(os.Stderr, "usage: main CASES.tsv")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	// split at "\n" only, so that a lone carriage return is not a line end
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	n, wrong := 0, []string{}
	for sc.Scan() {
		if sc.Text() == "" {
			continue
		}
		p := strings.Split(strings.TrimSuffix(sc.Text(), "\r"), "\t")
		if len(p) != 6 {
			fmt.Fprintln(os.Stderr, "bad line")
			os.Exit(2)
		}
		if p[5] != "0" && p[5] != "1" {
			fmt.Fprintln(os.Stderr, "bad expected result in case "+p[0])
			os.Exit(2)
		}
		pk, sig, msg, ctx := unhex(p[1]), unhex(p[2]), unhex(p[3]), unhex(p[4])
		got := verify(pk, sig, msg, ctx)
		n++
		if got != (p[5] == "1") {
			wrong = append(wrong, p[0])
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "no cases")
		os.Exit(2)
	}
	fmt.Printf("Go crypto/mldsa (%s): %d cases, %d disagree with the expected result %v\n", runtime.Version(), n, len(wrong), wrong)
	if len(wrong) > 0 {
		os.Exit(1)
	}
}
