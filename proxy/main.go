package main

import (
	"flag"

	"github.com/Trisia/gosysproxy"
)

func main() {
	var (
		proxy string
	)
	flag.StringVar(&proxy, "proxy", "", "netsh winhttp set proxy proxy-server=")
	flag.Parse()
	if proxy == "" {
		gosysproxy.SetPAC("")
		gosysproxy.Off()
	} else {
		gosysproxy.SetGlobalProxy(proxy)
	}
}
