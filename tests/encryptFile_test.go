package tests

import (
	"testing"

	"toukio.lib/encrypting/pkg/service"
)

func TestEncryptFile(t *testing.T) {
	//Teste Positivo
	t.Run("Criptografar e descriptografar arquivo de texto", func(t *testing.T) {
		s := service.NewService()
		//fazer parse de arquivo de chave privada
		privKey, err := s.ParsePrivateKey("private.pem")
		if err != nil {
			t.Errorf("erro ao fazer parse de arquivo de chave privada. Original: %s", err.Error())
		}
		//criptografar arquivo teste.txt
		ciphertext, err := s.EncryptFileTest("teste.txt", "encryptfiletest", privKey)
		if err != nil {
			t.Errorf("erro ao criptografar arquivo de teste. Original: %s", err.Error())
		}
		t.Log(ciphertext)
		//descriptografar arquivo texte.txt
		err = s.DecryptFileTest(ciphertext, "encryptfiletest", "decryptedTeste.txt", privKey)
		if err != nil {
			t.Errorf("erro ao descriptografar arquivo de teste. Original: %s", err.Error())
		}
	})
}
