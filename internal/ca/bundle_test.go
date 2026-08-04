package ca

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func testBundleInputs(t *testing.T) (certPEM, keyPEM, rootCert []byte) {
	t.Helper()
	cert := &x509.Certificate{Raw: []byte("cert-bytes")}
	root := &x509.Certificate{Raw: []byte("root-bytes")}
	return EncodeCertPEM(cert), []byte("-----BEGIN EC PRIVATE KEY-----\ndummy\n-----END EC PRIVATE KEY-----\n"), EncodeCertPEM(root)
}

func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	files := make(map[string][]byte)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = b
	}
	return files
}

func TestBundleZipContents(t *testing.T) {
	certPEM, keyPEM, rootCert := testBundleInputs(t)

	data, err := GenerateBundle(certPEM, keyPEM, rootCert, "syslog.example.com", 6514)
	if err != nil {
		t.Fatalf("generate bundle: %v", err)
	}

	files := unzip(t, data)
	for _, name := range []string{"ca.crt", "client.crt", "client.key", "60-signoz.conf", "install.sh"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("missing %s in bundle", name)
		}
	}
	if !bytes.Equal(files["ca.crt"], rootCert) {
		t.Fatal("ca.crt does not match root cert")
	}
	if !bytes.Equal(files["client.crt"], certPEM) {
		t.Fatal("client.crt does not match cert PEM")
	}
	conf := string(files["60-signoz.conf"])
	if !strings.Contains(conf, `queue.maxDiskSpace="1g"`) {
		t.Fatal("rsyslog conf missing queue.maxDiskSpace")
	}
	if !strings.Contains(conf, `queue.type="LinkedList"`) {
		t.Fatal("rsyslog conf missing queue.type")
	}
	sh := string(files["install.sh"])
	if !strings.Contains(sh, "#!/bin/sh") {
		t.Fatal("install.sh missing shebang")
	}
}

func TestBundleWithoutKey(t *testing.T) {
	certPEM, _, rootCert := testBundleInputs(t)

	data, err := GenerateBundle(certPEM, nil, rootCert, "host", 6514)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	files := unzip(t, data)
	if _, ok := files["client.key"]; ok {
		t.Fatal("client.key should be absent when keyPEM is nil")
	}
	if len(files) != 4 {
		t.Fatalf("expected 4 files, got %d", len(files))
	}
}

func TestBundleRsyslogConfigContainsHostname(t *testing.T) {
	certPEM, _, rootCert := testBundleInputs(t)

	data, _ := GenerateBundle(certPEM, nil, rootCert, "relay.example.com", 6514)
	files := unzip(t, data)
	conf := string(files["60-signoz.conf"])
	if !strings.Contains(conf, `Target="relay.example.com"`) {
		t.Fatal("conf missing Target hostname")
	}
	if !strings.Contains(conf, `Port="6514"`) {
		t.Fatal("conf missing port")
	}
}

func TestInstallShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not installed — skipping (informational)")
	}

	// Extract install.sh from a bundle
	certPEM, _, rootCert := testBundleInputs(t)
	data, _ := GenerateBundle(certPEM, nil, rootCert, "host", 6514)
	files := unzip(t, data)

	dir := t.TempDir()
	path := dir + "/install.sh"
	if err := os.WriteFile(path, files["install.sh"], 0755); err != nil {
		t.Fatalf("write install.sh: %v", err)
	}

	cmd := exec.Command("shellcheck", "-s", "sh", "-x", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shellcheck failed:\n%s", out)
	}
}

func TestPEMRoundTrip(t *testing.T) {
	certPEM, _, _ := testBundleInputs(t)
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("bad PEM block")
	}
}
