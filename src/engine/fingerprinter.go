package main

import (
	"strings"
)

type TechFingerprint struct {
	Name     string
	Check    func(headers map[string][]string, body string) bool
}

var fingerprints = []TechFingerprint{
	{
		Name: "express",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.ToLower(strings.Join(headers["X-Powered-By"], " ")), "express") ||
				headers["Set-Cookie"] != nil && strings.Contains(strings.Join(headers["Set-Cookie"], " "), "connect.sid")
		},
	},
	{
		Name: "php",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.ToLower(strings.Join(headers["X-Powered-By"], " ")), "php") ||
				strings.Contains(strings.Join(headers["Set-Cookie"], " "), "PHPSESSID")
		},
	},
	{
		Name: "react",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(body, "react.development.js") || strings.Contains(body, "react.production.min.js") ||
				strings.Contains(body, "_reactRootContainer")
		},
	},
	{
		Name: "django",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["Set-Cookie"], " "), "csrftoken") ||
				strings.Contains(body, "__admin_media_prefix__")
		},
	},
}

func Fingerprint(headers map[string][]string, body string) []string {
	var detected []string
	for _, fp := range fingerprints {
		if fp.Check(headers, body) {
			detected = append(detected, fp.Name)
		}
	}
	return detected
}
