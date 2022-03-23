package infra

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

//create certificate authority
func CreateCertificateAuthority(serialNumber big.Int, organization, country, province, locality, adress, postal string, expiresAt time.Time) *x509.Certificate {
	//create certificate with Is certificate authority(IsCA) = true
	authority := &x509.Certificate{
		SerialNumber: &serialNumber,
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{adress},
			PostalCode:    []string{postal},
		},
		NotBefore:             time.Now(),
		NotAfter:              expiresAt,
		IsCA:                  true, //Is certificate authority
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	//get certificate authority data
	// authData, err := x509.CreateCertificate(rand.Reader, authority, authority, &authPrivKey.PublicKey, authPrivKey)
	// if err != nil {
	// 	return nil, err
	// }

	return authority
}

//create private keys for certificates
func CreatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

//TODO: usar funções encode para criar arquivos .pem para o certificate authority
// func EncodeAuthority(authData []byte, authPrivKey *rsa.PrivateKey) {
// 	authPem := new(bytes.Buffer)
// 	pem.Encode(authPem, &pem.Block{
// 		Type:  "CERTIFICATE",
// 		Bytes: authData,
// 	})

// 	authPrivKeyPem := new(bytes.Buffer)
// 	pem.Encode(authPrivKeyPem, &pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(authPrivKey),
// 	})
// }

//create certificate
func CreateCertificate(serialNumber big.Int, organization, country, province, locality, adress, postal string, expiresAt time.Time, ips []net.IP, authority *x509.Certificate, privKey *rsa.PrivateKey) ([]byte, error) {
	certificate := &x509.Certificate{
		SerialNumber: &serialNumber,
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{adress},
			PostalCode:    []string{postal},
		},
		IPAddresses:  ips,
		NotBefore:    time.Now(),
		NotAfter:     expiresAt,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	//get certificate data
	certData, err := x509.CreateCertificate(rand.Reader, certificate, authority, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return certData, nil
}

//Create Pem Files
func CreateCertificatePemFiles(certData []byte, certPrivKey *rsa.PrivateKey, certFileName, keyFileName string) error {
	//encode certificate and key on PEM
	certPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	})

	certPrivKeyPem := new(bytes.Buffer)
	pem.Encode(certPrivKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	//creating pem files
	certFile, err := os.Create(certFileName)
	if err != nil {
		return err
	}
	keyFile, err := os.Create(keyFileName)
	if err != nil {
		return err
	}

	//writing data on files
	_, err = certFile.Write(certPem.Bytes())
	if err != nil {
		return err
	}
	defer certFile.Close()
	_, err = keyFile.Write(certPrivKeyPem.Bytes())
	if err != nil {
		return err
	}
	defer keyFile.Close()
	return nil
}
