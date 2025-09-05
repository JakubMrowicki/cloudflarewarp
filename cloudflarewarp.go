// Package cloudflarewarp Traefik Plugin.
package cloudflarewarp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

type contextKey string

var (
	// CFAPI is the Cloudflare API URL.
	CFAPI = "https://api.cloudflare.com/client/v4/ips"
)

const (
	// CTXHTTPTimeout is the context key for the HTTP timeout.
	CTXHTTPTimeout contextKey = "HTTPTimeout"
	// CTXTrustedIPs is the context key for the trusted IP ranges.
	CTXTrustedIPs contextKey = "TrustedIPs"
	// HTTPTimeoutDefault is the default HTTP timeout in seconds.
	HTTPTimeoutDefault = 5

	xRealIP        = "X-Real-Ip"
	xCfTrusted     = "X-Is-Trusted"
	xForwardFor    = "X-Forwarded-For"
	xForwardProto  = "X-Forwarded-Proto"
	cfConnectingIP = "Cf-Connecting-Ip"
	cfVisitor      = "Cf-Visitor"
)

// Config the plugin configuration.
type Config struct {
	// RefreshInterval is the interval between IP range updates
	RefreshInterval string `json:"refreshInterval,omitempty"`
	// TrustIP is a list of custom IP addresses or CIDR ranges that are allowed
	TrustIP []string `json:"trustip,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		RefreshInterval: "24h",
	}
}

// RealIPOverWriter is a plugin that overwrite true IP.
type RealIPOverWriter struct {
	next http.Handler
	name string

	ips             *ipstore
	refreshInterval time.Duration
	trustedIPs      []net.IPNet
}

// CFVisitorHeader definition for the header value.
type CFVisitorHeader struct {
	Scheme string `json:"scheme"`
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	ips := newIPStore(CFAPI)

	refreshInterval, err := time.ParseDuration(config.RefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh interval: %w", err)
	}

	trustedIPs, err := parseCIDRs(config.TrustIP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trusted IPs: %w", err)
	}

	ctxUpdate := createContext(ctx, HTTPTimeoutDefault, trustedIPs)

	if err := ips.Update(ctxUpdate); err != nil {
		return nil, fmt.Errorf("failed to update Cloudflare IP ranges: %w", err)
	}

	ipOverWriter := &RealIPOverWriter{
		next:            next,
		name:            name,
		ips:             ips,
		trustedIPs:      trustedIPs,
		refreshInterval: refreshInterval,
	}

	go ipOverWriter.refreshLoop(ctx)
	return ipOverWriter, nil
}

func (r *RealIPOverWriter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		http.Error(rw, "Unknown source", http.StatusInternalServerError)
		return
	}

	trusted := r.ips.Contains(remoteIP)

	if req.Header.Get(cfConnectingIP) == "" && trusted {
		req.Header.Set(xCfTrusted, "yes")
		r.next.ServeHTTP(rw, req)
		return
	}
	if req.Header.Get(cfConnectingIP) != "" && trusted {
		if req.Header.Get(cfVisitor) != "" {
			var cfVisitorValue CFVisitorHeader
			if err := json.Unmarshal([]byte(req.Header.Get(cfVisitor)), &cfVisitorValue); err != nil {
				req.Header.Set(xCfTrusted, "danger")
				req.Header.Del(cfVisitor)
				req.Header.Del(cfConnectingIP)
				r.next.ServeHTTP(rw, req)
				return
			}
			req.Header.Set(xForwardProto, cfVisitorValue.Scheme)
		}
		req.Header.Set(xCfTrusted, "yes")
		req.Header.Set(xForwardFor, req.Header.Get(cfConnectingIP))
		req.Header.Set(xRealIP, req.Header.Get(cfConnectingIP))
	} else {
		http.Error(rw, "Not Cloudflare or TrustedIP", http.StatusForbidden)
		return
	}
	r.next.ServeHTTP(rw, req)
}

// refreshLoop periodically updates the IP ranges.
func (r *RealIPOverWriter) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(r.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			ctxUpdate := createContext(ctx, HTTPTimeoutDefault, r.trustedIPs)

			if err := r.ips.Update(ctxUpdate); err != nil {
				log.Printf("Failed to update Cloudflare IP ranges: %v", err)
			}
		}
	}
}

type ipstore struct {
	cfAPI string
	atomic.Value
}

func newIPStore(cfURL string) *ipstore {
	ips := &ipstore{
		cfAPI: cfURL,
	}
	ips.Store([]net.IPNet{})
	return ips
}

func (ips *ipstore) Contains(ip net.IP) bool {
	cidrs, ok := ips.Load().([]net.IPNet)
	if !ok {
		return false
	}
	for _, ipNet := range cidrs {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// Update fetches the latest Cloudflare IP ranges and updates the store.
func (ips *ipstore) Update(ctx context.Context) error {
	trustedIPs, ok := ctx.Value(CTXTrustedIPs).([]net.IPNet)
	if !ok {
		return errors.New("invalid trusted IPs value")
	}

	fetchedCIDRs, err := ips.fetch(ctx)
	if err != nil {
		return err
	}

	cidrs := make([]net.IPNet, 0, len(trustedIPs)+len(fetchedCIDRs))
	cidrs = append(cidrs, trustedIPs...)
	cidrs = append(cidrs, fetchedCIDRs...)

	ips.Store(cidrs)
	return nil // Return nil if everything is successful
}

func (ips *ipstore) fetch(ctx context.Context) ([]net.IPNet, error) {
	timeout, ok := ctx.Value(CTXHTTPTimeout).(int) // Ensure timeout is of type int
	if !ok {
		return nil, errors.New("invalid timeout value")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ips.cfAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Printf("failed to close response body: %v", err)
		}
	}()

	// Check for a successful response
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", res.Status)
	}

	resp := CFResponse{}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return parseResponse(resp)
}

// CFResponse is a Cloudflare API response.
type CFResponse struct {
	Result   CFResponseResult    `json:"result"`
	Success  bool                `json:"success"`
	Errors   []CFResponseMessage `json:"errors"`
	Messages []CFResponseMessage `json:"messages"`
}

// CFResponseResult is a response result.
type CFResponseResult struct {
	// IPv4CIDRs is a list of IPv4 CIDR ranges that Cloudflare uses.
	IPv4CIDRs []string `json:"ipv4_cidrs"` //nolint:tagliatelle
	// IPv6CIDRs is a list of IPv6 CIDR ranges that Cloudflare uses.
	IPv6CIDRs []string `json:"ipv6_cidrs"` //nolint:tagliatelle
	// ETag is a unique identifier for the response.
	ETag string `json:"etag"`
}

// CFResponseMessage is a response message.
type CFResponseMessage struct {
	// Code is a message code.
	Code int `json:"code"`
	// Message is a human-readable message.
	Message string `json:"message"`
}

func createContext(ctx context.Context, timeout int, trustedIPs []net.IPNet) context.Context {
	ctx = context.WithValue(ctx, CTXHTTPTimeout, timeout)
	return context.WithValue(ctx, CTXTrustedIPs, trustedIPs)
}

func parseResponse(resp CFResponse) ([]net.IPNet, error) {
	ipv4CIDRs, err := parseCIDRs(resp.Result.IPv4CIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv4 CIDRs: %w", err)
	}
	ipv6CIDRs, err := parseCIDRs(resp.Result.IPv6CIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv6 CIDRs: %w", err)
	}
	return append(ipv4CIDRs, ipv6CIDRs...), nil
}

func parseCIDRs(ips []string) ([]net.IPNet, error) {
	trustedIPs := make([]net.IPNet, 0, len(ips))
	for _, ip := range ips {
		_, ipNet, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR: %w", err)
		}
		trustedIPs = append(trustedIPs, *ipNet)
	}
	return trustedIPs, nil
}