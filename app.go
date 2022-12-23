package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AVENTER-UG/util"
	"github.com/sirupsen/logrus"
)

// APIProxyPort is the Port where the service are listening
var APIProxyPort string

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

var srv http.Server
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
		if directory == (CacheDir+"/.") || strings.Contains(directory, "manifests") {
			return nil
		}

		if _, err := os.Stat(directory + "/" + filename); os.IsNotExist(err) {
			logrus.WithField("func", "modifyResponse").Debug("Write File: " + directory + "/" + filename)

			os.MkdirAll(directory, os.ModePerm)

			out, _ := os.Create(filepath.Clean(directory + "/" + filename))
			// #nosec G307
			defer out.Close()

			client := &http.Client{}
			// #nosec G402
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			req, _ := http.NewRequest(r.Request.Method, r.Request.URL.String(), nil)
			req.Header = r.Header
			res, _ := client.Do(req)

			// Write the body to file
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

	if fh, err := os.Stat(directory + "/" + filename); !errors.Is(err, os.ErrNotExist) {
		dateDiff := fh.ModTime().Sub(time.Now())

		if dateDiff.Hours() < (RetentionTime * -1) {
			logrus.WithField("func", "modifyRequest").Debug("Cleanup old file: " + directory + "/" + filename)
			os.Remove(directory + "/" + filename)
			return
		}

		if fh.Size() > 0 {
			logrus.WithField("func", "modifyRequest").Debug("Read File: " + directory + "/" + filename)

			r.URL.Host = "localhost:8080"
		}
	}
}

func reverseProxyLoop() {
	srv.Handler = &handle{reverseProxy: TargetURL}
	srv.Addr = APIProxyBind + ":" + APIProxyPort
	if err := srv.ListenAndServe(); err != nil {
		logrus.WithField("func", "main.reverseProxyLoop").Error(err.Error())
		srv.Close()
		reverseProxyLoop()
	}
}

func v2Directory(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, "{}")
}

func fileServerLoop() {
	fileServer := http.FileServer(http.Dir(CacheDir + ""))
	http.HandleFunc("/v2", v2Directory)
	http.Handle("/", fileServer)

	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		logrus.WithField("func", "main.fileServerLoop").Error(err.Error())
		fileServerLoop()
	}
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
