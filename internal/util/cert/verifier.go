package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
)

// VerifyTLSConfig checks if the provided certificate files are valid and match
func VerifyTLSConfig(certFile, keyFile, caCertFile string) error {
	// 1. Check file existence
	if _, err := os.Stat(certFile); err != nil {
		return errors.Wrapf(err, "server certificate file not found: %s", certFile)
	}
	if _, err := os.Stat(keyFile); err != nil {
		return errors.Wrapf(err, "server key file not found: %s", keyFile)
	}
	if _, err := os.Stat(caCertFile); err != nil {
		return errors.Wrapf(err, "CA certificate file not found: %s", caCertFile)
	}

	// 2. Load key pair (checks PEM parsing and key matching)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return errors.Wrap(err, "failed to load server certificate key pair")
	}

	// 3. Check expiry
	if len(cert.Certificate) == 0 {
		return errors.New("no certificate found in file")
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "failed to parse server certificate")
	}
	if time.Now().After(x509Cert.NotAfter) {
		return fmt.Errorf("server certificate expired at %s", x509Cert.NotAfter)
	}
	if time.Now().Before(x509Cert.NotBefore) {
		return fmt.Errorf("server certificate not valid until %s", x509Cert.NotBefore)
	}

	// 4. Load and verify CA cert
	caBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		return errors.Wrap(err, "failed to read CA certificate")
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caBytes) {
		return errors.New("failed to parse CA certificate")
	}

	// 5. Verify server cert against CA
	opts := x509.VerifyOptions{
		Roots: caCertPool,
	}
	if _, err := x509Cert.Verify(opts); err != nil {
		// Log detailed error but don't necessarily block if it's just a hostname mismatch in this context
		// (though without hostname in opts, it shouldn't check hostname)
		return errors.Wrap(err, "server certificate verification against CA failed")
	}

	return nil
}
