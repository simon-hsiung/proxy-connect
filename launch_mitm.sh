#!/bin/sh

PWD=$(dirname "${BASH_SOURCE[0]}")
docker run --rm -it -v ${PWD}/.mitmproxy:/home/mitmproxy/.mitmproxy -p 8080:8080 -p 8081:8081 mitmproxy/mitmproxy mitmweb --web-host 0.0.0.0

