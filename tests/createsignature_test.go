package tests

import (
	"testing"

	"toukio.lib/encrypting/pkg/service"
)

func TestCreateSignature(t *testing.T) {
	//Teste Positivo
	t.Run("Testar criação de assinatura usando chave privada", func(t *testing.T) {
		s := service.NewSignDocumentService()
		//assinar arquivo pdf
		signature, err := s.CreateSignature("testingsignature", "private.pem")
		if err != nil {
			t.Errorf("erro ao criar assinatura. Original: %s", err.Error())
		}
		if len(signature) == 0 {
			t.Errorf("erro ao retornar assinatura vazia. Original: %s", signature)
		}
		//verify signature
		err = s.CheckSignature("testingsignature", "private.pem", signature)
		if err != nil {
			t.Errorf("erro durante verificação de assinatura. Original: %s", err.Error())
		}
	})
}
