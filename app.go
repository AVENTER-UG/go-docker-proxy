package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AVENTER-UG/util/util"
	"github.com/sirupsen/logrus"
)

// APIProxyPort is the Port where the service are listening
var APIProxyPort int

// APIProxyBind is the IP where the service are listening
var APIProxyBind string

// TargetURL is the Url to where the proxy will forward all access
var TargetURL string

// SkipSSL will disable the ssl check
var SkipSSL string

// BlockAgent include a regularexpression to denied access of specified user agents
var BlockAgent string

// BlockURL include a regularexpression to denied access of specified url
var BlockURL string

// LogLevel defines the loglevel
var LogLevel string

// MinVersion is just the version of e app, its set dynamic during compiling
var MinVersion string

// CacheDir is the directory where we store the container blobs
var CacheDir string

// RetentionTime is the time after we delete to blobs
var RetentionTime float64

// SSLKey for the cache server
var SSLKey string

// SSLCrt for the cache server
var SSLCrt string

var reAgent *regexp.Regexp
var reURL *regexp.Regexp

type handle struct {
	reverseProxy string
}

func (e *handle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logrus.WithField("func", "ServeHTTP").Debug(e.reverseProxy + " " + r.Method + " " + r.URL.String() + " " + r.Proto + " " + r.UserAgent())

	if BlockAgent != "" {
		fi := reAgent.Find([]byte(r.UserAgent()))
		if len(fi) > 0 {
			logrus.Debug("Blocked: ", r.UserAgent())
			return
		}
	}

	if BlockURL != "" {
		fi := reURL.Find([]byte(r.URL.String()))
		if len(fi) > 0 {
			logrus.Debug("Blocked: ", r.URL.String())
			return
		}
	}

	remote, err := url.Parse(e.reverseProxy)
	if err != nil {
		logrus.Error(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		modifyRequest(req)
	}
	proxy.ModifyResponse = modifyResponse()

	if SkipSSL == "true" {
		proxy.Transport = &http.Transport{
			// #nosec G402
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	proxy.ServeHTTP(w, r)

}

func modifyResponse() func(*http.Response) error {
	return func(r *http.Response) error {
		filename := path.Base(r.Request.URL.String())
		directory := CacheDir + "/" + path.Dir(strings.Trim(r.Request.URL.String(), TargetURL))

		// do not cache manifest files
		if !strings.Contains(directory, "blobs") || strings.Contains(directory, strconv.Itoa(APIProxyPort+1)) {
			return nil
		}

		if _, err := os.Stat(directory + "/" + filename); os.IsNotExist(err) {
			logrus.WithField("func", "modifyResponse").Debug("Write File: " + directory + "/" + filename)

			err = os.MkdirAll(directory, os.ModePerm)
			if err != nil {
				logrus.WithField("func", "modifyRequest").Error(err.Error())
			}

			out, _ := os.Create(filepath.Clean(directory + "/" + filename))
			// #nosec G307
			defer out.Close()

			client := &http.Client{}
			// #nosec G402
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}

			req, _ := http.NewRequest(r.Request.Method, r.Request.URL.String(), http.NoBody)
			req.Header = r.Request.Header
			res, _ := client.Do(req)

			// Write the body to fildocker pull dockregproxy.marathon.slave.mesos:10666/aggrviews/attr-aggviews-facebook:teste
			_, err := io.Copy(out, res.Body)

			if err != nil {
				logrus.WithField("func", "modifyRequest").Error(err.Error())
			}
		}
		return nil
	}
}

func modifyRequest(r *http.Request) {
	filename := filepath.Clean(path.Base(r.URL.String()))
	directory := filepath.Clean(CacheDir + "/" + path.Dir(strings.Trim(r.URL.String(), TargetURL)))

	if filename == "v2" {
		return
	}
	if fh, err := os.Stat(directory + "/" + filename); !errors.Is(err, os.ErrNotExist) {
		dateDiff := time.Until(time.Now())

		if dateDiff.Hours() < (RetentionTime * -1) {
			logrus.WithField("func", "modifyRequest").Debug("Cleanup old file: " + directory + "/" + filename)
			os.Remove(directory + "/" + filename)
			return
		}

		if fh.Size() > 0 {
			logrus.WithField("func", "modifyRequest").Debug("Read File: " + directory + "/" + filename)
			if SSLCrt != "" && SSLKey != "" {
				r.URL.Scheme = "https"
			}
			r.URL.Host = "127.0.0.1:" + strconv.Itoa(APIProxyPort+1)
		}
	}
}

func reverseProxyLoop() {
	var err error

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(APIProxyPort),
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		Handler:           &handle{reverseProxy: TargetURL},
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
		},
	}

	if SSLCrt != "" && SSLKey != "" {
		logrus.WithField("func", "reverseProxyLoop").Debug("Enable TLS")
		crt := decodeBase64Cert(SSLCrt)
		key := decodeBase64Cert(SSLKey)
		var certs tls.Certificate
		certs, err = tls.X509KeyPair(crt, key)
		if err != nil {
			logrus.WithField("func", "reverseProxyLoop").Fatal("TLS Server Error: ", err.Error())
		}
		server.TLSConfig.Certificates = []tls.Certificate{certs}
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}

	if err != nil {
		logrus.WithField("func", "reverseProxyLoop").Error(err.Error())
		server.Close()
		reverseProxyLoop()
	}
}

func fileServerLoop() {
	var err error

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(APIProxyPort+1),
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
		},
	}

	http.Handle("/", http.FileServer(http.Dir(CacheDir)))

	if SSLCrt != "" && SSLKey != "" {
		logrus.WithField("func", "fileServerLoop").Debug("Enable TLS")
		crt := decodeBase64Cert(SSLCrt)
		key := decodeBase64Cert(SSLKey)
		var certs tls.Certificate
		certs, err = tls.X509KeyPair(crt, key)
		if err != nil {
			logrus.WithField("func", "fileServerLoop").Fatal("TLS Server Error: ", err.Error())
		}
		server.TLSConfig.Certificates = []tls.Certificate{certs}
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}

	if err != nil {
		logrus.WithField("func", "fileServerLoop").Error(err.Error())
		server.Close()
		fileServerLoop()
	}
}

func decodeBase64Cert(pemCert string) []byte {
	sslPem, err := base64.URLEncoding.DecodeString(pemCert)
	if err != nil {
		logrus.WithField("func", "decodeBase64Cert").Fatal("Error decoding SSL PEM from Base64: ", err.Error())
	}
	return sslPem
}

func main() {
	util.SetLogging(LogLevel, false, "go-proxy")
	logrus.Infoln("GO-DOCKER-PROXY build"+MinVersion, APIProxyBind, APIProxyPort, TargetURL, SkipSSL)

	if BlockAgent != "" {
		logrus.Infoln("Block following Agents: ", BlockAgent)
		var err error
		reAgent, err = regexp.Compile(BlockAgent)

		if err != nil {
			logrus.Error(err)
		}
	}

	if BlockURL != "" {
		logrus.Infoln("Block following Url: ", BlockURL)
		var err error
		reURL, err = regexp.Compile(BlockURL)

		if err != nil {
			logrus.Error(err)
		}
	}

	go reverseProxyLoop()
	fileServerLoop()
}
