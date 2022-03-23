package tests

import (
	"math/big"
	"net"
	"testing"
	"time"

	"toukio.lib/encrypting/internal/infra"
)

func TestCreateCertificatePemFiles(t *testing.T) {
	//Teste Positivo
	t.Run("Criar arquivo pem para chave e certificado", func(t *testing.T) {
		//criar chave privada para certificate authority
		// caPrivKey, err := infra.CreatePrivateKey(4096)
		// if err != nil {
		// 	t.Errorf("erro ao criar chave privada para authority. Original: %s", err.Error())
		// }
		serial := big.NewInt(2019)
		//criar certificate authority para usar no certificado
		authority := infra.CreateCertificateAuthority(*serial, "Company, INC.", "US", "", "San Francisco", "Golden Gate Bridge", "94016", time.Now().AddDate(10, 0, 0))
		//criar chave privada para certificado
		certificatePrivKey, err := infra.CreatePrivateKey(4096)
		if err != nil {
			t.Errorf("erro ao criar chave privada do certificado. Original: %s", err.Error())
		}
		serial = big.NewInt(1658)
		ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		//criar certificado
		certificate, err := infra.CreateCertificate(*serial, "Company, INC.", "US", "", "San Francisco", "Golden Gate Bridge", "94016", time.Now().AddDate(10, 0, 0), ips, authority, certificatePrivKey)
		if err != nil {
			t.Errorf("erro ao criar certificado. Original: %s", err.Error())
		}
		//criar arquivos .pem para certificado e para chave privada do certificado
		err = infra.CreateCertificatePemFiles(certificate, certificatePrivKey, "certificate.pem", "private.pem")
		if err != nil {
			t.Errorf("erro ao criar arquivos .pem do certificado e chave privada. Original: %s", err.Error())
		}
	})
}
