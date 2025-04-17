# Proxy Connection Test

Some tests to clarify the error while connecting to proxy over HTTPS.

In conclusion, we may have problem while connecting to some proxy server (like mitmproxy)
when the first element in [`tls.Config.NextProtos`](https://cs.opensource.google/go/go/+/refs/tags/go1.24.1:src/crypto/tls/common.go;l=662)
is "h2".
