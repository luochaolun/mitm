package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	//"crypto/x509"
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	//"strings"
)

// A very simple http proxy

const (
	rsaBits    = 2048
	certFolder = "cert"
)

var (
	mu sync.Mutex
)

func main() {
	simpleProxyHandler := http.HandlerFunc(simpleProxyHandlerFunc)
	http.ListenAndServe(":8888", simpleProxyHandler)
	//createCerts("test")
}

func logRequest(r *http.Request, add string) {
	fmt.Println(add)
	fmt.Println("Host", r.Host)
	fmt.Println("Url", r.URL.String())
	fmt.Println("Mehtod", r.Method)
	fmt.Println("--------------")
}

func buildHttpsUrl(r *http.Request) *url.URL {
	url, err := url.Parse("https://" + r.Host + r.URL.String())
	if err != nil {
		fmt.Println("error", err.Error())
	}
	return url
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func getCertPath(hostname string) (string, string) {
	cert := path.Join(certFolder, hostname+".pem")
	key := path.Join(certFolder, hostname+".key")
	return cert, key
}

func handleResponse(resp *http.Response) {
	//fmt.Println(resp.Proto)
	//fmt.Println("%+v\n", resp)
	/*tp := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(tp, "text/"){
		return
	}*/

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	//fmt.Println(string(raw))

	buf1 := bytes.NewBuffer(raw)
	bufReader := ioutil.NopCloser(buf1)
	resp.Body = bufReader

	buf2 := bytes.NewBuffer(raw)

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(buf2)
		if err != nil {
			return
		}
		defer reader.Close()
	default:
		reader = ioutil.NopCloser(buf2)
	}

	handleBody(reader)
	//io.Copy(os.Stdout, reader)
}

func handleBody(reader io.ReadCloser) {
	if reader == nil {
		return
	}

	buf := new(bytes.Buffer)
	n, err := buf.ReadFrom(reader)

	if n == 0 || (err != nil) {
		return
	}

	s := strings.TrimSpace(buf.String())
	fmt.Println(s)
}

func simpleProxyHandlerFunc(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		hostname := strings.Split(r.Host, ":")[0]
		//fmt.Println("cert for ", hostname)

		certFile, keyFile := getCertPath(hostname)

		if !pathExists(certFile) {
			//log.Println("creating cert for", hostname)
			createCerts(hostname)
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		checkError(err)

		config := tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}

		conn, buff, err := hj.Hijack()
		buff.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		//fmt.Println("sending ok ", r.URL.String())
		buff.Flush()

		go (func() {
			if err != nil {
				return
			}
			defer conn.Close()

			tlsCon := tls.Server(conn, &config)
			clientTlsReader := bufio.NewReader(tlsCon)
			clientTlsWriter := bufio.NewWriter(tlsCon)
			tlsCon.Handshake()

			for {
				r, err := http.ReadRequest(clientTlsReader)
				if err != nil {
					//fmt.Println(err.Error())
					return
				}

				//httpc := &http.Client{}

				r.RequestURI = ""
				r.URL = buildHttpsUrl(r)

				//logRequest(r, "https")
				resp, err := http.DefaultTransport.RoundTrip(r)

				if err != nil {
					//fmt.Println("https http client error ", err.Error())
					continue
				}
				//fmt.Println("%#v\n", resp)
				handleResponse(resp)
				resp.Write(clientTlsWriter)
				clientTlsWriter.Flush()
			}
		})()
	} else {
		httpc := &http.Client{}
		// request uri can't be set in client requests
		r.RequestURI = ""
		resp, err := httpc.Do(r)

		if err != nil {
			//logRequest(r, "http, error:"+err.Error())
			//fmt.Println(err.Error())
			return
		}

		copyHeaders(w.Header(), resp.Header)
		// copy content
		defer resp.Body.Close()
		dumpResp, _ := httputil.DumpResponse(resp, true)
		fmt.Println(string(dumpResp))
		io.Copy(w, resp.Body)
	}
}

func copyHeaders(dest http.Header, source http.Header) {
	for header := range source {
		dest.Add(header, source.Get(header))
	}
}

func checkError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func createCerts(hostName string) {
	mu.Lock()
	defer mu.Unlock()

	caCertFile := "mymitm.crt"
	caKeyFile := "mymitm.key"

	certFile, keyFile := getCertPath(hostName)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63n(time.Now().Unix())),
		Subject: pkix.Name{
			Country:            []string{"DE"},
			Organization:       []string{"PPP"},
			OrganizationalUnit: []string{"MMM"},
			CommonName:         hostName,
		},

		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().AddDate(10, 0, 0).UTC(),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:     []string{hostName},
		//PermittedDNSDomains: []string{name},
	}

	if ip := net.ParseIP(hostName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostName)
	}

	var err error = nil
	var rootCA tls.Certificate

	rootCA, err = tls.LoadX509KeyPair(caCertFile, caKeyFile)
	checkError(err)

	rootCA.Leaf, err = x509.ParseCertificate(rootCA.Certificate[0])
	checkError(err)

	var priv *rsa.PrivateKey

	priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	checkError(err)

	var derBytes []byte

	derBytes, err = x509.CreateCertificate(rand.Reader, template, rootCA.Leaf, &priv.PublicKey, rootCA.PrivateKey)
	checkError(err)

	if !pathExists(certFolder) {
		os.Mkdir(certFolder, 0777)
	}

	certOut, err := os.Create(certFile)
	checkError(err)

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	checkError(err)

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}
