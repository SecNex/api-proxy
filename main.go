package main

import (
	"git.secnex.io/secnex/api-proxy/config"
	"git.secnex.io/secnex/api-proxy/server"
)

func main() {
	// proxyConfig := config.NewProxyConfig(
	// 	"8001",
	// 	"admin",
	// 	"password",
	// 	"http://localhost:8000/token",
	// 	"http://localhost:8000",
	// 	"xxxx",
	// 	"xxxx",
	// )
	proxyConfig := config.NewProxyConfigFromEnv()
	proxy, err := server.NewProxyServer(proxyConfig)
	if err != nil {
		panic(err)
	}
	proxy.Start()
}
