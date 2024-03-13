package exporter

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"strings"

	"github.com/go-kit/log/level"
	"github.com/prometheus/common/promlog"
	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

func ListenAndServeTLS(conf Config) {

	promlogConfig := promlog.Config{
		Level:  &promlog.AllowedLevel{},
		Format: &promlog.AllowedFormat{},
	}
	promlogConfig.Level.Set("info")
	promlogConfig.Format.Set("logfmt")

	logger := promlog.New(&promlogConfig)

	var tlsCert tls.Certificate

	if strings.ToUpper(conf.CertType) == CERTTYPE_PKCS12 {

		if strings.HasSuffix(conf.Pkcs12File, ".pem") {
			pemData, err := os.ReadFile(conf.Pkcs12File)
			if err != nil {
				level.Error(logger).Log("Error reading PEM file", err)
			}
			pemBlock, _ := pem.Decode(pemData)
			if pemBlock == nil {
				level.Error(logger).Log("Error decoding PEM file", err)
				return
			}
			der, err := pkcs8.ParsePKCS8PrivateKey(pemBlock.Bytes, []byte(conf.Pkcs12Pass))
			if err != nil {
				level.Error(logger).Log("Error decrpting PEM file", err)
				return
			}
			privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(der)
			if err != nil {
				level.Error(logger).Log("Error MarshalPrivateKey", err)
				return
			}
			privateKeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}))

			tlsCert, err = tls.X509KeyPair(pemData, []byte(privateKeyPem))
			if err != nil {
				level.Error(logger).Log("PEM - Error loading keypair", err)
				return
			}
		} else if strings.HasSuffix(conf.Pkcs12File, ".p12") {

			// Read byte data from pkcs12 keystore
			p12_data, err := os.ReadFile(conf.Pkcs12File)
			if err != nil {
				level.Error(logger).Log("Error reading PKCS12 file", err)
				return
			}

			// Extract cert and key from pkcs12 keystore
			privateKey, leafCert, caCerts, err := pkcs12.DecodeChain(p12_data, conf.Pkcs12Pass)
			if err != nil {
				level.Error(logger).Log("PKCS12 - Error decoding chain", err)
				return
			}

			certBytes := [][]byte{leafCert.Raw}
			for _, ca := range caCerts {
				certBytes = append(certBytes, ca.Raw)
			}
			tlsCert = tls.Certificate{
				Certificate: certBytes,
				PrivateKey:  privateKey,
			}
		}
	} else {
		var err error
		tlsCert, err = tls.LoadX509KeyPair(conf.Certificate, conf.PrivateKey)
		if err != nil {
			level.Error(logger).Log("PEM - Error loading keypair", err)
			return
		}
	}

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		Certificates: []tls.Certificate{tlsCert},
	}
	http := &http.Server{
		Addr:         conf.ListenAddr,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	if err := http.ListenAndServeTLS("", ""); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(2)
	}

}
