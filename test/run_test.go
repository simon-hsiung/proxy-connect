package test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
)

/**/
const (
	proxyHost   = "localhost" //"10.8.144.42"
	proxyPort   = "8080"
	proxyAddr   = proxyHost + ":" + proxyPort
	proxyCAFile = "../.mitmproxy/mitmproxy-ca-cert.pem"
)

/**/

/*
const (
	proxyHost = "squid.yourdomain.com" //"localhost" //"10.8.144.42"
	proxyPort = "3128"
	proxyAddr = proxyHost + ":" + proxyPort
	//	proxyCAFile = "../.squid/root-ca.crt"
	proxyCAFile = "../.mitmproxy/mitmproxy-ca-cert.pem"
)
/**/

// Request via a proxy connected over HTTP.
// This will fail due to certificate verification.
func Test_X_Request_Http_Url(t *testing.T) {
	c := client().
		SetProxy("http://" + proxyHost + ":" + proxyPort)
	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTP and bind the root CA.
// This will succeed.
func Test_O_Request_Http_Url_WithCA(t *testing.T) {
	c := client().
		SetProxy("http://" + proxyHost + ":" + proxyPort).
		SetRootCertificate(proxyCAFile)
	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTPS and bind the root CA.
// This will fail due to a malformed protocol.
func Test_X_Request_Https_Url(t *testing.T) {
	c := client().
		SetProxy("https://" + proxyHost + ":" + proxyPort).
		SetRootCertificate(proxyCAFile)
	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTPS by modifying transport.
// This is similar to the above test and will also fail.
func Test_X_Request_Https_Transport(t *testing.T) {
	c := client().
		SetRootCertificate(proxyCAFile)

	transport, err := c.Transport()
	require.Nil(t, err)

	transport.Proxy = http.ProxyURL(&url.URL{
		Scheme: "https",
		Host:   proxyHost + ":" + proxyPort,
	})
	transport.TLSClientConfig.InsecureSkipVerify = false

	c.SetTransport(transport)

	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTPS by modifying transport.
// Even with TLS verification disabled,
// this will still fail due to a malformed protocol.
func Test_X_Request_Https_Transport_Insecure(t *testing.T) {
	c := client().
		SetRootCertificate(proxyCAFile)

	transport, err := c.Transport()
	require.Nil(t, err)

	transport.Proxy = http.ProxyURL(&url.URL{
		Scheme: "https",
		Host:   proxyHost + ":" + proxyPort,
	})
	transport.TLSClientConfig.InsecureSkipVerify = true

	c.SetTransport(transport)

	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTPS using a new transport.
// This will fail during certificate verification.
func Test_X_Request_Https_New_Transport(t *testing.T) {
	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "https",
			Host:   proxyHost + ":" + proxyPort,
		}),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	c := client().
		SetRootCertificate(proxyCAFile)
	c.SetTransport(transport)

	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTPS using a new transport, same as above.
// Skipping TLS verification will let the request succeed.
func Test_O_Request_Https_New_Transport_Insecure(t *testing.T) {
	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "https",
			Host:   proxyHost + ":" + proxyPort,
		}),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	c := client()
	c.SetTransport(transport)

	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTPS using a new transport, same as above.
// Binding the root CA can also let the request succeed.
func Test_O_Request_Https_New_Transport_WithCA(t *testing.T) {
	tlsConf := &tls.Config{InsecureSkipVerify: false}
	if !bindRootCA(tlsConf, proxyCAFile) {
		fmt.Println("failed to bind root CA")
		t.Fatal()
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "https",
			Host:   proxyHost + ":" + proxyPort,
		}),
		TLSClientConfig: tlsConf,
	}

	c := client()
	c.SetTransport(transport)

	doGet(t, c, "https://www.google.com")
}

// Request via a proxy connected over HTTPS by modifying transport.
// If we remove the NextProtos, the request will succeed.
func Test_O_Request_Https_Transport_No_NextProtos(t *testing.T) {
	c := client().
		SetRootCertificate(proxyCAFile)

	transport, err := c.Transport()
	require.Nil(t, err)

	transport.Proxy = http.ProxyURL(&url.URL{
		Scheme: "https",
		Host:   proxyHost + ":" + proxyPort,
	})
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig.NextProtos = nil
	transport.TLSClientConfig.InsecureSkipVerify = false

	fmt.Println("NextProtos: ", transport.TLSClientConfig.NextProtos)
	c.SetTransport(transport)

	resp, err := c.R().Get("https://www.google.com")
	fmt.Println("NextProtos: ", transport.TLSClientConfig.NextProtos)
	if err != nil {
		fmt.Println("request failed, err: ", err)
		t.Fatal()
	}
	fmt.Println("Status code:", resp.StatusCode())
}

func doGet(t *testing.T, c *resty.Client, url string) {
	resp, err := c.R().Get(url)
	if err != nil {
		fmt.Println("request failed, err: ", err)
		t.Fatal()
	}
	fmt.Println("Status code:", resp.StatusCode())
}

// Connect to a proxy using the CONNECT method.
// This will fail due to certificate verification.
func Test_X_ProxyConnect(t *testing.T) {
	cfg := &tls.Config{}

	doConnect(t, cfg, proxyHost, proxyPort, "www.google.com:443")
}

// Connect to a proxy using the CONNECT method, and bind the root CA.
// This will succeed.
func Test_O_ProxyConnectWithCA(t *testing.T) {
	cfg := &tls.Config{}
	bindRootCA(cfg, proxyCAFile)

	doConnect(t, cfg, proxyHost, proxyPort, "www.google.com:443")
}

// Connect to a proxy using the CONNECT method, and bind the root CA.
// If we set the first NextProtos to "h2",
// this fails due to a malformed protocol.
func Test_X_ProxyConnectWithCAAndALPN(t *testing.T) {
	cfg := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	bindRootCA(cfg, proxyCAFile)

	doConnect(t, cfg, proxyHost, proxyPort, "www.google.com:443")
}

func doConnect(
	t *testing.T,
	cfg *tls.Config,
	pHost, pPort string,
	targetAddr string,
) {
	ctx := context.Background()

	pAddr := pHost + ":" + pPort
	conn, err := zeroDialer.DialContext(ctx, "tcp", pAddr)
	if err != nil {
		fmt.Println("failed to connect to proxy: ", err)
		t.Fatal()
	}

	cfg.ServerName = pHost
	conn, err = addTLS(ctx, conn, cfg)
	if err != nil {
		fmt.Println("failed to add TLS: ", err)
		t.Fatal()
	}

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: targetAddr},
		Host:   pHost,
		Header: make(http.Header),
	}
	if err = connectReq.Write(conn); err != nil {
		fmt.Println("failed to write request: ", err)
		t.Fatal()
	}

	tp := textproto.NewReader(bufio.NewReader(conn))
	line, err := tp.ReadLine()
	if err != nil {
		fmt.Println("failed to read response: ", err)
		t.Fatal()
	}

	fmt.Println("conn response: ", line)

	// copied from golang http.ReadResponse
	// https://github.com/golang/go/blob/go1.24.1/src/net/http/response.go#L154
	badStringError := func(what, val string) string { return fmt.Sprintf("%s %q\n", what, val) }

	proto, status, ok := strings.Cut(line, " ")
	if !ok {
		fmt.Println(badStringError("malformed HTTP response", line))
		t.Fatal()
	}

	statusCode, _, _ := strings.Cut(status, " ")
	if len(statusCode) != 3 {
		fmt.Println(badStringError("malformed HTTP status code", statusCode))
		t.Fatal()
	}

	StatusCode, err := strconv.Atoi(statusCode)
	if err != nil || StatusCode < 0 {
		// If the status code is not a number, it is a malformed response.
		fmt.Println(badStringError("malformed HTTP status code", statusCode))
		t.Fatal()
	}

	_, _, ok = http.ParseHTTPVersion(proto)
	if !ok {
		fmt.Println("malformed HTTP version: ", proto)
		t.Fatal()
	}

	line, err = tp.ReadLine()
	if err != nil {
		fmt.Println("next line: ", line)
	}
}
