package main

import (
	"flag"
	"os"
	"os/exec"

	"github.com/Trisia/gosysproxy"
)

func main() {
	var (
		proxy,
		bypass string
	)
	flag.StringVar(&proxy, "proxy-server", "", "netsh winhttp set proxy proxy-server=host[:port][;{http|https|ftp|socks}=host[:port]]")
	flag.StringVar(&bypass, "bypass-list", "", `netsh winhttp set proxy bypass-list={"<local>"|host}[;host]`)
	flag.Parse()
	cmd := exec.Command("netsh",
		"winhttp",
		"show",
		"proxy",
	)
	if len(os.Args) > 1 {
		if proxy == "" {
			gosysproxy.SetPAC("")
			gosysproxy.Off()
		} else {
			gosysproxy.SetGlobalProxy(proxy, bypass)
		}
		cmd = exec.Command("netsh",
			"winhttp",
			"import",
			"proxy",
			"ie",
		)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Run()
}
