package config

import "git.secnex.io/secnex/api-proxy/utils"

type ProxyConfig struct {
	Port        string
	TargetHost  string
	TokenApiUrl string
}

func NewProxyConfig(port, targetHost, TokenApiUrl string) *ProxyConfig {
	return &ProxyConfig{
		Port:        port,
		TargetHost:  targetHost,
		TokenApiUrl: TokenApiUrl,
	}
}

func NewProxyConfigFromEnv() *ProxyConfig {
	return NewProxyConfig(
		*utils.GetEnv("PORT", "8000"),
		*utils.GetEnvOnly("TARGET_HOST"),
		*utils.GetEnvOnly("API_TOKEN_URL"),
	)
}
