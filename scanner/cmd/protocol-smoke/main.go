package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lcvvvv/gonmap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: protocol-smoke host:port[,host:port...]")
		os.Exit(2)
	}
	scanner := gonmap.New()
	scanner.SetTimeout(3 * time.Second)
	for _, raw := range strings.Split(os.Args[1], ",") {
		host, portStr, ok := strings.Cut(raw, ":")
		if !ok {
			fmt.Printf("skip %s\n", raw)
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			fmt.Printf("skip %s\n", raw)
			continue
		}
		status, resp := scanner.Scan(host, port)
		svc, product, version, rawBanner := "", "", "", ""
		if resp != nil {
			rawBanner = resp.Raw
			if resp.FingerPrint != nil {
				svc = resp.FingerPrint.Service
				product = resp.FingerPrint.ProductName
				version = resp.FingerPrint.Version
			}
		}
		if len(rawBanner) > 80 {
			rawBanner = rawBanner[:80]
		}
		fmt.Printf("%s status=%s service=%q product=%q version=%q raw=%q\n",
			raw, status, svc, product, version, rawBanner)
	}
}
