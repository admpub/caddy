package dnsproviders

import "os"

func LookupEnv(key string, fallback string) string {
	if value, exists := os.LookupEnv(key); exists && len(value) > 0 {
		return value
	}
	return fallback
}

func LookupEnvAnyKey(keys []string, fallback string) string {
	for _, key := range keys {
		if value, exists := os.LookupEnv(key); exists && len(value) > 0 {
			return value
		}
	}
	return fallback
}
