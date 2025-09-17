package main

import (
	"os"
	"strconv"

	"github.com/AVENTER-UG/util/util"
)

func init() {
	APIProxyBind = util.Getenv("API_PROXYBIND", "0.0.0.0")
	APIProxyPort, _ = strconv.Atoi(util.Getenv("API_PROXYPORT", "10777"))
	TargetURL = os.Getenv("TARGET_URL")
	SkipSSL = util.Getenv("SKIP_SSL", "false")
	BlockAgent = os.Getenv("BLOCK_USERAGENT")
	BlockURL = os.Getenv("BLOCK_URL")
	LogLevel = util.Getenv("LOGLEVEL", "info")
	CacheDir = util.Getenv("CACHEDIR", "./cache")
	RetentionTime, _ = strconv.ParseFloat(util.Getenv("RETENTION", "24"), 64)
	SSLKey = util.Getenv("SSL_KEY_BASE64", "")
	SSLCrt = util.Getenv("SSL_CRT_BASE64", "")
}
