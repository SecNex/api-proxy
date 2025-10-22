package utils

import "os"

func GetEnv(key, def string) *string {
	if val, ok := os.LookupEnv(key); ok {
		return &val
	}
	return &def
}

func GetEnvOnly(key string) *string {
	if val, ok := os.LookupEnv(key); ok {
		return &val
	}
	return nil
}
