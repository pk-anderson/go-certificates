package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

type Service interface {
	ParsePrivateKey(keyfile string) (*rsa.PrivateKey, error)
	EncryptFileTest(file, labelname string, privKey *rsa.PrivateKey) ([]byte, error)
	DecryptFileTest(ciphertext []byte, labelname, decryptedFileName string, privKey *rsa.PrivateKey) error
}

type encryptService struct {
}

func (s *encryptService) ParsePrivateKey(keyfile string) (*rsa.PrivateKey, error) {
	//read file
	priv, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("error on reading private key file: %s", err.Error())
	}
	//decode file bytes
	block, _ := pem.Decode(priv)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("error on decoding file bytes: %s", err.Error())
	}
	//parse private key
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error on parsing private key: %s", err.Error())
	}
	return privKey, nil
}

func (s *encryptService) EncryptFileTest(file, labelname string, privKey *rsa.PrivateKey) ([]byte, error) {
	//read file
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error on reading file: %s", err.Error())
	}
	//get label
	label := []byte(labelname)
	//get public key from private key
	publicKey := &privKey.PublicKey
	//encrypt file
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, label)
	if err != nil {
		return nil, fmt.Errorf("error on encrypting file: %s", err.Error())
	}
	return ciphertext, nil
}

func (s *encryptService) DecryptFileTest(ciphertext []byte, labelname, decryptedFileName string, privKey *rsa.PrivateKey) error {
	label := []byte(labelname)
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, label)
	if err != nil {
		return fmt.Errorf("error on decrypting file from ciphertext: %s", err.Error())
	}
	file, err := os.Create(decryptedFileName)
	if err != nil {
		return fmt.Errorf("error on creating decrypted file: %s", err.Error())
	}
	_, err = file.Write(plaintext)
	if err != nil {
		return fmt.Errorf("error on writing in decrypted file: %s", err.Error())
	}
	return nil
}

func NewService() Service {
	return &encryptService{}
}
