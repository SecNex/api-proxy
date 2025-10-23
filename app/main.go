package main

import (
	"git.secnex.io/secnex/api-proxy/config"
	"git.secnex.io/secnex/api-proxy/server"
)

func main() {
	proxyConfig := config.NewProxyConfigFromEnv()
	proxy, err := server.NewProxyServer(proxyConfig)
	if err != nil {
		panic(err)
	}
	proxy.Start()
}
