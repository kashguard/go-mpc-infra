package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Certificate management tools",
	}

	cmd.AddCommand(newGenCmd())
	return cmd
}

func newGenCmd() *cobra.Command {
	var outDir string
	var hostnames []string

	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate development certificates (CA, Server, Client)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := generateCerts(outDir, hostnames); err != nil {
				log.Fatal().Err(err).Msg("Failed to generate certificates")
			}
		},
	}

	cmd.Flags().StringVarP(&outDir, "out", "o", "certs", "Output directory for certificates")
	cmd.Flags().StringSliceVar(&hostnames, "host", []string{"localhost", "127.0.0.1", "coordinator", "participant-1", "participant-2", "participant-3"}, "Hostnames/IPs for server certificate")

	return cmd
}

func generateCerts(outDir string, hostnames []string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// 1. Generate CA
	log.Info().Msg("Generating CA certificate...")
	caPriv, caCert, caPEM, caPrivPEM, err := generateCA()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "ca.crt"), caPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "ca.key"), caPrivPEM, 0600); err != nil {
		return err
	}

	// 2. Generate Server Certificate
	log.Info().Strs("hosts", hostnames).Msg("Generating Server certificate...")
	serverPEM, serverPrivPEM, err := generateEntityCert("mpc-server", hostnames, caCert, caPriv, true)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "server.crt"), serverPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "server.key"), serverPrivPEM, 0600); err != nil {
		return err
	}

	// 3. Generate Client Certificate (Infrastructure Layer)
	log.Info().Msg("Generating Client certificate (Infrastructure)...")
	clientPEM, clientPrivPEM, err := generateEntityCert("mpc-infrastructure-client", nil, caCert, caPriv, false)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "client.crt"), clientPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "client.key"), clientPrivPEM, 0600); err != nil {
		return err
	}

	// 4. Generate Node Certificates (Protocol Layer)
	// For mTLS between nodes, each node needs a cert. We can reuse server cert if it covers all hostnames,
	// or generate specific ones. For simplicity, we'll generate a generic "node" cert.
	log.Info().Msg("Generating Node certificate (Protocol)...")
	nodePEM, nodePrivPEM, err := generateEntityCert("mpc-node", hostnames, caCert, caPriv, true) // Nodes act as both server and client
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "node.crt"), nodePEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "node.key"), nodePrivPEM, 0600); err != nil {
		return err
	}

	log.Info().Str("dir", outDir).Msg("Certificates generated successfully")
	return nil
}

func generateCA() (*rsa.PrivateKey, *x509.Certificate, []byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MPC Wallet CA"},
			CommonName:   "MPC Wallet Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return priv, template, certPEM, privPEM, nil
}

func generateEntityCert(cn string, hosts []string, caCert *x509.Certificate, caKey *rsa.PrivateKey, isServer bool) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"MPC Wallet"},
			CommonName:   cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, privPEM, nil
}
