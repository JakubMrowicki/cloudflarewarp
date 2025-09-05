package cloudflarewarp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	plugin "github.com/jakubmrowicki/cloudflarewarp"
)

const (
	// Cloudflare API mock response
	cfAPIMockResponse = `{` +
		`"result":{` +
		`"ipv4_cidrs":["173.245.48.0/20","103.21.244.0/22"],` +
		`"ipv6_cidrs":["2400:cb00::/32","2606:4700::/32"],` +
		`"etag":"38f79d050aa027e3be3865e495dcc9bc"` +
		`},` +
		`"success":true,` +
		`"errors":[]` +
		`,"messages":[]` +
		`}`
)

func newTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		fmt.Fprint(rw, cfAPIMockResponse)
	}))
}

func TestNew(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	// Temporarily modify the CFAPI constant to point to the test server
	plugin.CFAPI = server.URL

	cfg := plugin.CreateConfig()
	cfg.TrustIP = []string{"172.18.0.1/32"}

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	handler, err := plugin.New(ctx, next, cfg, "cloudflarewarp")
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		ipv6           bool
		expect400      bool
		trusted        bool
		remote         string
		desc           string
		cfConnectingIP string
		cfVisitor      string
		expected       string
		expectedScheme string
	}{
		{
			remote:         "103.21.244.23",
			desc:           "blank scheme",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "",
			expected:       "10.0.0.1",
			expectedScheme: "",
			trusted:        true,
		},
		{
			remote:         "103.21.244.23",
			desc:           "https scheme",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "{\"scheme\":\"https\"}",
			expected:       "10.0.0.1",
			expectedScheme: "https",
			trusted:        true,
		},
		{
			remote:         "10.0.1.20",
			desc:           "not trust",
			cfConnectingIP: "127.0.0.2",
			cfVisitor:      "",
			expected:       "",
			expectedScheme: "",
			trusted:        false,
		},
		{
			remote:         "2400:cb00::1",
			ipv6:           true,
			desc:           "trusted ipv6",
			cfConnectingIP: "1001:3984:3989::1",
			cfVisitor:      "",
			expected:       "1001:3984:3989::1",
			expectedScheme: "",
			trusted:        true,
		},
		{
			remote:         "172.18.0.1",
			desc:           "custom trusted ip",
			cfConnectingIP: "10.0.0.1",
			cfVisitor:      "",
			expected:       "10.0.0.1",
			expectedScheme: "",
			trusted:        true,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.ipv6 == true {
				req.RemoteAddr = "[" + test.remote + "]:36001"
			} else {
				req.RemoteAddr = test.remote + ":36001"
			}
			req.Header.Set("X-Real-Ip", test.remote)
			req.Header.Set("Cf-Connecting-Ip", test.cfConnectingIP)
			req.Header.Set("Cf-Visitor", test.cfVisitor)

			handler.ServeHTTP(recorder, req)

			if !test.trusted {
				if recorder.Result().StatusCode != http.StatusForbidden {
					t.Errorf("invalid response status code: %d, expected %d", recorder.Result().StatusCode, http.StatusForbidden)
				}
				return
			}

			if recorder.Result().StatusCode != http.StatusOK {
				t.Errorf("invalid response: %s", strconv.Itoa(recorder.Result().StatusCode))
				return
			}

			assertHeader(t, req, "X-Is-Trusted", "yes")
			assertHeader(t, req, "X-Real-Ip", test.expected)
			assertHeader(t, req, "X-Forwarded-For", test.expected)
			assertHeader(t, req, "X-Forwarded-Proto", test.expectedScheme)
		})
	}
}

func TestError(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.TrustIP = []string{"103.21.244.0"}
	cfg.RefreshInterval = "invalid-duration"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := plugin.New(ctx, next, cfg, "cloudflarewarp")
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header(%s) value: %s, expected: %s", key, req.Header.Get(key), expected)
	}
}