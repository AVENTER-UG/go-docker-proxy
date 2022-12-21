package main

import (
	"os"

	"github.com/AVENTER-UG/util"
)

func init() {
	APIProxyBind = util.Getenv("API_PROXYBIND", "0.0.0.0")
	APIProxyPort = util.Getenv("API_PROXYPORT", "10777")
	TargetURL = os.Getenv("TARGET_URL")
	SkipSSL = util.Getenv("SKIP_SSL", "false")
	BlockAgent = os.Getenv("BLOCK_USERAGENT")
	BlockURL = os.Getenv("BLOCK_URL")
	LogLevel = util.Getenv("LOGLEVEL", "info")
}
