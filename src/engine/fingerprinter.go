package main

import (
	"math/rand"
	"strings"

	utls "github.com/refraction-networking/utls"
)

type TechFingerprint struct {
	Name  string
	Check func(headers map[string][]string, body string) bool
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
	{
		Name: "aws",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.ToLower(strings.Join(headers["Server"], " ")), "awselb") ||
				strings.Contains(strings.ToLower(strings.Join(headers["X-Amz-Cf-Id"], " ")), "") && len(headers["X-Amz-Cf-Id"]) > 0
		},
	},
	{
		Name: "gcp",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["Server"], " "), "UploadServer") ||
				strings.Contains(strings.Join(headers["X-Cloud-Trace-Context"], " "), "") && len(headers["X-Cloud-Trace-Context"]) > 0
		},
	},
	{
		Name: "azure",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["X-Ms-Invokeapp"], " "), "") && len(headers["X-Ms-Invokeapp"]) > 0 ||
				strings.Contains(strings.Join(headers["Set-Cookie"], " "), "ARRAffinity")
		},
	},
	{
		Name: "vercel",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["X-Vercel-Id"], " "), "") && len(headers["X-Vercel-Id"]) > 0 ||
				strings.Contains(strings.Join(headers["Server"], " "), "Vercel")
		},
	},
	{
		Name: "netlify",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["X-Nf-Request-Id"], " "), "") && len(headers["X-Nf-Request-Id"]) > 0 ||
				strings.Contains(strings.Join(headers["Server"], " "), "Netlify")
		},
	},
	{
		Name: "fly.io",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["Server"], " "), "Fly.io") ||
				strings.Contains(strings.Join(headers["Fly-Request-Id"], " "), "") && len(headers["Fly-Request-Id"]) > 0
		},
	},
	{
		Name: "render",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["X-Render-Origin"], " "), "") && len(headers["X-Render-Origin"]) > 0
		},
	},
	{
		Name: "railway",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["X-Railway-Request-Id"], " "), "") && len(headers["X-Railway-Request-Id"]) > 0
		},
	},
	{
		Name: "digitalocean",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["Server"], " "), "do-haproxy") ||
				strings.Contains(strings.Join(headers["X-Do-Request-Id"], " "), "") && len(headers["X-Do-Request-Id"]) > 0
		},
	},
	{
		Name: "vultr",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["Server"], " "), "Vultr")
		},
	},
	{
		Name: "hetzner",
		Check: func(headers map[string][]string, body string) bool {
			return strings.Contains(strings.Join(headers["Server"], " "), "Hetzner")
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

func GetTLSProfile() utls.ClientHelloID {
	profiles := []utls.ClientHelloID{
		utls.HelloChrome_120,
		utls.HelloChrome_102,
		utls.HelloFirefox_105,
		utls.HelloFirefox_120,
		utls.HelloSafari_16_0,
		utls.HelloEdge_106,
	}
	return profiles[rand.Intn(len(profiles))]
}

func ApplyStealthTLS(uconn *utls.UConn) error {
	if err := uconn.BuildHandshakeState(); err != nil {
		return err
	}

	for _, ext := range uconn.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	return nil
}
