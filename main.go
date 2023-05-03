package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Ouest-France/k8s-dashboard-auth-proxy/provider"
	"github.com/Ouest-France/k8s-dashboard-auth-proxy/proxy"
)

func main() {
	// Define and parse flags
	auth := flag.String("auth", "aws-adfs", "Authentication provider (aws-adfs, tanzu)")
	loginURL := flag.String("login-url", "", "ADFS or Tanzu login URL")
	dashboardURL := flag.String("dashboard-url", "http://127.0.0.1:9090/", "Dashboard URL to proxy")
	clusterID := flag.String("cluster-id", "", "Kubernetes cluster ID (only for AWS-ADFS)")
	tanzuGuestCluster := flag.String("tanzu-guest-cluster", "", "Tanzu guest cluster name (only for Tanzu)")
	debug := flag.Bool("debug", false, "Debug mode")
	flag.Parse()

	// Check login URL
	if *loginURL == "" {
		fmt.Println("Login URL must be set")
		os.Exit(1)
	}

	// Create provider
	var authProvider provider.Provider
	var err error
	switch *auth {
	case "aws-adfs":
		authProvider, err = provider.NewProviderAwsAdfs(*loginURL, *clusterID)
		if err != nil {
			fmt.Printf("Failed to create AWS-ADFS provider: %s\n", err)
			os.Exit(1)
		}
	case "tanzu":
		authProvider, err = provider.NewProviderTanzu(*loginURL, *tanzuGuestCluster)
		if err != nil {
			fmt.Printf("Failed to create Tanzu provider: %s\n", err)
			os.Exit(1)
		}
	default:
		fmt.Println("Auth provider must be 'aws-adfs' or 'tanzu'")
		os.Exit(1)
	}

	// Server requests
	err = proxy.Server(*dashboardURL, authProvider, *debug)
	if err != nil {
		fmt.Printf("Failed to start proxy: %s", err)
		os.Exit(1)
	}
}
