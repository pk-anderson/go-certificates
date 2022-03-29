package tests

import (
	"testing"

	"toukio.lib/encrypting/pkg/service"
)

func TestSignDoc(t *testing.T) {
	//Teste Positivo
	t.Run("Testar criação de assinatura usando chave privada", func(t *testing.T) {
		s := service.NewSignDocumentService()
		//assinar arquivo pdf
		signature, err := s.SignDoc("private.pem", "hello.pdf")
		if err != nil {
			t.Errorf("erro ao criar assinatura. Original: %s", err.Error())
		}
		if len(signature) == 0 {
			t.Errorf("erro ao retornar assinatura vazia: %s", signature)
		}
		//check signature
		err = s.CheckSignedDoc("private.pem", "hello.pdf", signature)
		if err != nil {
			t.Errorf("erro ao verificar assinatura. Original: %s", err.Error())
		}
	})
}
