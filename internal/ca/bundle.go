package ca

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"text/template"
)

//go:embed templates/install.sh.tmpl
var installShTmpl string

//go:embed templates/rsyslog.conf.tmpl
var rsyslogConfTmpl string

type bundleData struct {
	Hostname string
	Port     int
}

// GenerateBundle builds a zip with ca.crt, client.crt, client.key (optional),
// 60-signoz.conf, and install.sh.
func GenerateBundle(certPEM, keyPEM, rootCert []byte, hostname string, syslogPort int) ([]byte, error) {
	return generateZip(certPEM, keyPEM, rootCert, hostname, syslogPort)
}

// GenerateDownloadOnlyBundle is the same zip used for single-use downloads.
func GenerateDownloadOnlyBundle(certPEM, keyPEM, rootCert []byte, hostname string, syslogPort int) ([]byte, error) {
	return generateZip(certPEM, keyPEM, rootCert, hostname, syslogPort)
}

func generateZip(certPEM, keyPEM, rootCert []byte, hostname string, syslogPort int) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	write := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}

	if err := write("ca.crt", rootCert); err != nil {
		return nil, err
	}
	if err := write("client.crt", certPEM); err != nil {
		return nil, err
	}
	if len(keyPEM) > 0 {
		if err := write("client.key", keyPEM); err != nil {
			return nil, err
		}
	}

	t, err := template.New("rsyslog").Parse(rsyslogConfTmpl)
	if err != nil {
		return nil, err
	}
	var confBuf bytes.Buffer
	if err := t.Execute(&confBuf, bundleData{Hostname: hostname, Port: syslogPort}); err != nil {
		return nil, err
	}
	if err := write("60-signoz.conf", confBuf.Bytes()); err != nil {
		return nil, err
	}

	if err := write("install.sh", []byte(installShTmpl)); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
