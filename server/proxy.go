package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"git.secnex.io/secnex/api-proxy/config"
)

type ProxyServer struct {
	proxy  *Proxy
	config *config.ProxyConfig
}

type Proxy httputil.ReverseProxy

func NewProxyServer(config *config.ProxyConfig) (*ProxyServer, error) {
	targetURL, err := url.Parse(config.TargetHost)
	if err != nil {
		log.Printf("[ERROR] Failed to parse target URL: %s - %v", config.TargetHost, err)
		return nil, err
	}

	log.Printf("[INIT] Proxy server initialized. Target: %s", targetURL.String())

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	return &ProxyServer{
		proxy:  (*Proxy)(proxy),
		config: config,
	}, nil
}

func (p *ProxyServer) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != p.config.Username || pass != p.config.Password {
			log.Printf("[AUTH] Unauthorized access attempt from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		log.Printf("[AUTH] Successful authentication for user: %s", user)
		next.ServeHTTP(w, r)
	})
}

func RequestHandler(p *ProxyServer) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Log der eingehenden Anfrage
		log.Printf("[INCOMING] %s %s from %s | User-Agent: %s",
			r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())

		proxy := (*httputil.ReverseProxy)(p.proxy)

		tempReq := r.Clone(r.Context())
		originalDirector := proxy.Director
		proxy.Director(tempReq)

		log.Printf("[TARGET] Forwarding to: %s", tempReq.URL.String())

		proxy.Director = originalDirector

		accessTokenTarget := *p.getToken()
		if len(accessTokenTarget) > 0 {
			r.Header.Set("Authorization", "Bearer "+accessTokenTarget)
			log.Printf("[AUTH] Bearer token added to request")
		}

		wrappedWriter := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		proxy.ServeHTTP(wrappedWriter, r)

		duration := time.Since(startTime)
		if wrappedWriter.statusCode >= 400 {
			log.Printf("[RESPONSE] ❌ Status: %d | Duration: %v | Path: %s | Target: %s",
				wrappedWriter.statusCode, duration, r.URL.Path, tempReq.URL.String())
		} else {
			log.Printf("[RESPONSE] ✅ Status: %d | Duration: %v | Path: %s",
				wrappedWriter.statusCode, duration, r.URL.Path)
		}
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (p *ProxyServer) getToken() *string {
	url := p.config.TokenApiUrl

	body := strings.NewReader("grant_type=client_credentials")

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		fmt.Println("Fehler beim Erstellen der Anfrage:", err)
		return nil
	}

	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", p.config.ClientId, p.config.ClientSecret)))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil
	}

	if token, ok := result["access_token"].(string); ok {
		return &token
	}

	return nil
}

func (p *ProxyServer) Start() error {
	log.Printf("[SERVER] Starting proxy server on port %s", p.config.Port)
	log.Printf("[SERVER] Target host: %s", p.config.TargetHost)

	mux := http.NewServeMux()
	mux.HandleFunc("/", RequestHandler(p))

	authenticatedHandler := p.AuthMiddleware(mux)

	log.Printf("[SERVER] Server listening on :%s", p.config.Port)
	return http.ListenAndServe(":"+p.config.Port, authenticatedHandler)
}
