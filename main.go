package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Ouest-France/k8s-dashboard-auth-proxy/proxy"
)

func main() {

	// Define and parse flags
	var loginURL, guestClusterName, proxyURL string
	flag.StringVar(&loginURL, "login-url", "", "WCP login URL")
	flag.StringVar(&guestClusterName, "guest-cluster-name", "", "Tanzu guest cluster name")
	flag.StringVar(&proxyURL, "proxy-url", "http://127.0.0.1:9090/", "Dashboard URL to proxy")
	flag.Parse()

	// Check that loginURL and guestClusterName are set
	if loginURL == "" || guestClusterName == "" {
		fmt.Println("-login-url and -guest-cluster-name flags must be defined")
		os.Exit(1)
	}

	// Server requests
	err := proxy.Server(loginURL, guestClusterName, proxyURL)
	if err != nil {
		fmt.Printf("failed to start proxy: %s", err)
		os.Exit(1)
	}
}
