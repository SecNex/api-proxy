package config

import "git.secnex.io/secnex/api-proxy/utils"

type ProxyConfig struct {
	Port        string
	Username    string
	Password    string
	TargetHost  string
	TokenApiUrl string
}

func NewProxyConfig(port, username, password, targetHost, TokenApiUrl string) *ProxyConfig {
	return &ProxyConfig{
		Port:        port,
		Username:    username,
		Password:    password,
		TargetHost:  targetHost,
		TokenApiUrl: TokenApiUrl,
	}
}

func NewProxyConfigFromEnv() *ProxyConfig {
	return NewProxyConfig(
		*utils.GetEnv("PORT", "8000"),
		*utils.GetEnvOnly("USERNAME"),
		*utils.GetEnvOnly("PASSWORD"),
		*utils.GetEnvOnly("TARGET_HOST"),
		*utils.GetEnvOnly("API_TOKEN_URL"),
	)
}
