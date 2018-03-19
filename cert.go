// golang ssl证书相关处理

package main

import (
	"crypto"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"log"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"
)

var (
	mu        sync.Mutex
	certCache = map[string]*tls.Certificate{}
)

func (proxy *MiTMProxy) findOrCreateCert(host string) (*tls.Certificate, error) {
	mu.Lock()
	defer mu.Unlock()

	cert := certCache[host]
	if cert != nil {
		//proxy.info("cert is found in cache : %s", host)
		// TODO: check expires
		return cert, nil
	}

	//proxy.info("signing cert for : %s", host)
	cert, err := proxy.signHostCert([]string{host})
	if err == nil {
		certCache[host] = cert
	}

	return cert, err
}

func (proxy *MiTMProxy) signHostCert(hosts []string) (*tls.Certificate, error) {
	//mu.Lock()
	//defer mu.Unlock()

	now := time.Now()

	sortedHosts := make([]string, len(hosts))
	copy(sortedHosts, hosts)
	sort.Strings(sortedHosts)

	start := now.Add(-time.Minute)
	end := now.Add(3 * 365 * 24 * time.Hour)

	h := sha1.New()
	for _, host := range sortedHosts {
		h.Write([]byte(host))
	}
	binary.Write(h, binary.BigEndian, start)
	binary.Write(h, binary.BigEndian, end)
	hash := h.Sum(nil)
	serial := big.Int{}
	serial.SetBytes(hash)

	ca := proxy.signingCertificate
	x509ca := ca.certificate

	template := x509.Certificate{
		SerialNumber: &serial,
		//SignatureAlgorithm: x509ca.SignatureAlgorithm,
		//Issuer:             x509ca.Subject,
		Subject: pkix.Name{
			CommonName:   hosts[0],
			Organization: []string{"Sample MiTM Proxy untrusted CA"},
		},
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		//KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             start,
		NotAfter:              end,
		//IsCA:           false,
		//MaxPathLen:     0,
		//MaxPathLenZero: true,
		//DNSNames:       hosts,
	}

	if ip := net.ParseIP(hosts[0]); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = hosts
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, &template, x509ca, x509ca.PublicKey, ca.privateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes, x509ca.Raw},
		PrivateKey:  ca.privateKey,
	}
	return cert, nil
}

type signingCertificate struct {
	certificate *x509.Certificate
	privateKey  crypto.PrivateKey
}

func (proxy *MiTMProxy) setupCert(certfile, keyfile string) {
	ca, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		log.Fatalf("could not load key pair: %v", err)
	}

	x509ca, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		log.Fatalf("Invalid certificate : %v", err)
	}

	proxy.signingCertificate = signingCertificate{
		certificate: x509ca,
		privateKey:  ca.PrivateKey,
	}
}
