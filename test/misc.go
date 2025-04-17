package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"time"

	"github.com/go-resty/resty/v2"
)

func client() *resty.Client {
	return resty.New().
		SetRetryCount(0).
		SetTimeout(3000 * time.Second)
}

func bindRootCA(cfg *tls.Config, caFile string) bool {
	rootPemData, err := os.ReadFile(caFile)
	if err != nil {
		panic(err)
	}

	if cfg.RootCAs == nil {
		cfg.RootCAs = x509.NewCertPool()
	}
	return cfg.RootCAs.AppendCertsFromPEM(rootPemData)
}

var zeroDialer net.Dialer

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

// copy from golang code
// https://github.com/golang/go/blob/339c903a75c3fe936fb4ed6c355d15e6081d6af3/src/net/http/transport.go#L1681
func addTLS(ctx context.Context, plainConn net.Conn, cfg *tls.Config) (*tls.Conn, error) {
	// Initiate TLS and check remote host name against certificate.
	// cfg := cloneTLSConfig(pconn.t.TLSClientConfig)
	// if cfg.ServerName == "" {
	// 	cfg.ServerName = name
	// }
	// if pconn.cacheKey.onlyH1 {
	// 	cfg.NextProtos = nil
	// }
	tlsConn := tls.Client(plainConn, cfg)
	errc := make(chan error, 2)
	go func() {
		err := tlsConn.HandshakeContext(ctx)
		errc <- err
	}()
	if err := <-errc; err != nil {
		plainConn.Close()
		if err == (tlsHandshakeTimeoutError{}) {
			// Now that we have closed the connection,
			// wait for the call to HandshakeContext to return.
			<-errc
		}
		return nil, err
	}
	// cs := tlsConn.ConnectionState()
	// pconn.tlsState = &cs
	return tlsConn, nil
}
