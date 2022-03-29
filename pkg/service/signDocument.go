package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type SignDocumentService interface {
	CreateSignature(messageString, keyfile string) ([]byte, error)
	CheckSignature(messageString, keyfile string, signature []byte) error
	SignDoc(keyfile, filename string) ([]byte, error)
	CheckSignedDoc(keyfile, filename string, signature []byte) error
}

type signDocumentServiceImpl struct {
}

func (s *signDocumentServiceImpl) CreateSignature(messageString, keyfile string) ([]byte, error) {
	privKey, err := parseKey(keyfile)
	if err != nil {
		return nil, fmt.Errorf("error on parsing key: %s", err.Error())
	}
	//hash message
	message := []byte(messageString)
	msgHash := sha256.New()
	_, err = msgHash.Write(message)
	if err != nil {
		return nil, fmt.Errorf("error on creating hash: %s", err.Error())
	}
	//TODO: verificar valor que deve ser atribuído no sum
	msgHashSum := msgHash.Sum(nil)
	//generate signature
	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return nil, fmt.Errorf("error on creating signature: %s", err.Error())
	}
	return signature, nil
}

func (s *signDocumentServiceImpl) CheckSignature(messageString, keyfile string, signature []byte) error {
	privKey, err := parseKey(keyfile)
	if err != nil {
		return fmt.Errorf("error on parsing key: %s", err.Error())
	}
	//hash message
	message := []byte(messageString)
	msgHash := sha256.New()
	_, err = msgHash.Write(message)
	if err != nil {
		return fmt.Errorf("error on creating hash: %s", err.Error())
	}
	msgHashSum := msgHash.Sum(nil)
	//verify signature
	err = rsa.VerifyPSS(&privKey.PublicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		return fmt.Errorf("error on verifying signature: %s", err.Error())
	}
	return nil
}

func (s *signDocumentServiceImpl) SignDoc(keyfile, filename string) ([]byte, error) {
	//get private key
	privKey, err := parseKey(keyfile)
	if err != nil {
		return nil, fmt.Errorf("error on parsing key: %s", err.Error())
	}
	//read file
	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error on reading file: %s", err.Error())
	}
	//hash message
	msgHash := sha256.New()
	_, err = msgHash.Write(fileData)
	if err != nil {
		return nil, fmt.Errorf("error on creating hash: %s", err.Error())
	}
	msgHashSum := msgHash.Sum(nil)
	//sign document
	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return nil, fmt.Errorf("error on creating signature: %s", err.Error())
	}
	return signature, nil
}

func (s *signDocumentServiceImpl) CheckSignedDoc(keyfile, filename string, signature []byte) error {
	privKey, err := parseKey(keyfile)
	if err != nil {
		return fmt.Errorf("error on parsing key: %s", err.Error())
	}
	//read file
	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error on reading file: %s", err.Error())
	}
	//hash message
	msgHash := sha256.New()
	_, err = msgHash.Write(fileData)
	if err != nil {
		return fmt.Errorf("error on creating hash: %s", err.Error())
	}
	msgHashSum := msgHash.Sum(nil)
	//verify signature
	err = rsa.VerifyPSS(&privKey.PublicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		return fmt.Errorf("document signature does not match: %s", err.Error())
	}
	return nil
}

func parseKey(keyfile string) (*rsa.PrivateKey, error) {
	privKeyBytes, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("error on reading private key file: %s", err.Error())
	}
	privKeyBlock, _ := pem.Decode(privKeyBytes)
	if privKeyBlock == nil || privKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("error on decoding file bytes: %s", err.Error())
	}
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error on parsing private key: %s", err.Error())
	}
	return privKey, nil
}

func NewSignDocumentService() SignDocumentService {
	return &signDocumentServiceImpl{}
}
