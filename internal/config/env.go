package config

import (
	"strings"
)

const sp_allowPrefix = "SP_ALLOW_"

// getAllowFromEnv reads allowlist regex strings from environment variables.
//
// Environment variables should be of the form
// like SP_ALLOW_GET, SP_ALLOW_GET_0, SP_ALLOW_GET_1, SP_ALLOW_POST
// returning a map of method to list of regex strings.
// like: {"GET":[], "POST":[]}
func getAllowFromEnv(env []string) map[string][]string {
	result := make(map[string][]string)
	for _, v := range env {
		if v, ok := strings.CutPrefix(v, sp_allowPrefix); ok {
			key, value, found := strings.Cut(v, "=")
			if found {
				// optional number suffix after method
				method, _, _ := strings.Cut(key, "_")
				result[method] = append(result[method], value)
			}
		}
	}
	return result
}
