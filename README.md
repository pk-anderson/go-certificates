README

# 1. Criação de certificado e private key usando Go e x509

### 1.1. Criar Certificado do tipo Certificate Authority 

1 - Primeiro deve ser criado o Certificate Authority que será utilizado para assinar os Certificados do tipo x509 criados posteriormente. No Exemplo, isso foi feito em **internal/infra/certificates.go**, na função **CreateCertificateAuthority**.
2 - Utiliza-se a struct &x509.Certificate do pacote "crypto/x509", que pede algumas informações sobre o certificado, que foram passados como argumentos na função de exemplo. 
**OBS**: A documentação não especifica as informações que são obrigatórias, logo, creio que qualquer uma delas pode ser deixada em branco.
3 - É utilizado o mesmo struct para criação normal de certificados. A diferença é que aqui, o campo IsCA (Is Certificate Authority) é passado como true.
4 - Um exemplo da criação de Certificate Authority pode ser visto em **tests/createcertificatepemfiles_test.go**:
```
serial := big.NewInt(2019)
authority := infra.CreateCertificateAuthority(*serial, "Company, INC.", "US", "", "San Francisco", "Golden Gate Bridge", "94016", time.Now().AddDate(10, 0, 0))
```
5 - O último argumento é a data em que o certificado expira, do tipo time.Time.

**OBS** É possível criar uma chave privada para o authority para transforma-lo em um []byte e posteriormente fazer um encode para criar arquivos .pem para o authority e a key, mas não foi necessário por enquanto.

### 1.2. Criação de private key para assinar o certificado

1 - Antes de criar o certificado, é necessário criar a chave privada para assiná-lo. É possível criá-la usando a função **rsa.GenerateKey**, do pacote "crypto/rsa", que retorna um *rsa.PrivateKey.
2 - Essa função usa um rand.Reader do pacote "crypto/rand" e número de bits referentes ao tamanho que a chave terá.
3 - Exemplo de função para criar chave pode ser visto em **internal/infra/certificates.go**:
```
    func CreatePrivateKey(bits int) (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}
```

### 1.3. Criação do certificado usando o authority e a private key

1 - Utiliza-se a struct &x509.Certificate do pacote "crypto/x509", da mesma forma que em 1.1. A diferença é que aqui, o struct não terá a opção IsCA como true, e também irá passar um array de endereços de ip onde o certificado será válido, em IPAddresses no struct Certificate. Ex:
```
IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
```
2 - Assim, será criado um certificado do tipo *x509.Certificate, do pacote "crypto/x509". Em seguida, se pode gerar seus dados em formato de []byte, usando a função x509.CreateCertificate(). Essa função utiliza um:
-Reader => rand.Reader
-Template de certificate => usa-se o certificado *x509.Certificate criado acima.
-Parent => usa-se o authority criado em 1.1.
-Chave pública => retirada da privKey criada em 1.2. Ex: &privKey.PublicKey
-Chave privada => privKey criadda em 1.2.
```
Exemplo de função para criação de certificado em internal/infra/certificates.go:
    certData, err := x509.CreateCertificate(rand.Reader, certificate, authority, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}
```
3 - Essa função irá retornar um []bytes pertencente ao certificate, que será usada para criar o seu arquivo .pem.

### 1.4. Criação dos arquivos .pem para o certificado e a private key

1 - Primeiro, cria-se bytes.Buffer para armazenar o Encode de blocos do tipo &pem.Block, do pacote "encoding/pem", onde se determina o tipo CERTIFICATE para o certificado e o tipo RSA PRIVATE KEY para a chave. 

2 - É necessário passar o []byte do certificado adquirido em 1.3, e o []byte da chave privada adquirido usando a função x509.MarshalPKCS1PrivateKey(chave privada adquirida em 1.2). Utiliza-se o pem.Encode do pacote "encoding/pem".
Exemplo na função CreateCertificatePemFiles() em internal/infra/certificates.go
```
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
``` 

3 - Em seguida, é criado um arquivo .pem para o certificado e um para a chave usando os.Create, passando o nome do arquivo.
Exemplo:
```
    certFile, err := os.Create(string certFileName)
	if err != nil {
		return err
	}
	keyFile, err := os.Create(string keyFileName)
	if err != nil {
		return err
	}
```

4 - É escrito nesses arquivos (certFile e keyFile) os .Bytes() da cada um dos bytes.Buffer criados acima (certPem.Bytes() e certPrivKeyPem.Bytes()).
Exemplo:
```
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
```
5 - Feito isso, serão escritos os arquivos .pem para o certificado e key.

# 2. Exemplo de como Criptografar e Descriptografar arquivo usando o .pem da chave privada

### 2.1 - Fazer o parse do arquivo .pem da private key

1 - Antes de criptografar ou descriptografar, é necessário fazer o parse da private key. Para isso deve-se:
-Ler o arquivo .pem:
```
    priv, err := ioutil.ReadFile(string com nome do arquivo)
	if err != nil {
		return nil, fmt.Errorf("error on reading private key file: %s", err.Error())
	}
```
-Utilizar o []byte priv adquirido acima para verificar se o arquivo é do tipo RSA PRIVATE KEY e fazer o decode em um pem.Block do pacote "encoding/pem":
```
    block, _ := pem.Decode(priv)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("error on decoding file bytes: %s", err.Error())
	}
```
-Fazer o parse do block acima usando x509.ParsePKCS1PrivateKey([]byte do block):
```
    privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error on parsing private key: %s", err.Error())
	}
```
2 - Aqui, a privKey já poderá ser usada nas funções de Encrypt e Decrypt. Exemplo pode ser visto em **pkg/service/encryptFileExample.go** na função ParsePrivateKey()

### 2.2 - Fazer encrypt de arquivo txt

1 - Será necessário a chave adquirida acima, o nome do arquivo e uma string do label (rótulo de identificação) que a criptografia receberá. Primeiro deve-se ler o arquivo
```
    data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error on reading file: %s", err.Error())
	}
```

2 - Deve-se criar um []byte com a string referente ao label e retirar a public key utilizando a private key adquirida em 2.1.
```
label := []byte(labelname)
publicKey := &privKey.PublicKey
```

3- Utiliza-se a função rsa.EncryptOAEP do pacote "crypto/rsa" para criptografar os dados do arquivo. A função pede:
hash => sha256.New()
random io.Reader => rand.Reader
chave pública => publicKey adquirida acima
arquivo => []byte data 
label => []byte label
```
    ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, label)
	if err != nil {
		return nil, fmt.Errorf("error on encrypting file: %s", err.Error())
	}
```
4 - Essa função retorna um []byte referente a cifra do arquivo criptografado (ciphertext)
**OBS**: O tamanho da chave utilizada deve ser proporcional ao tamanho do arquivo que se pretende criptografar.

### 2.3 - Fazer decrypt de arquivo txt criptografado em 2.2

1 - Será necessário ciphertext adquirido em 2.2, a string com a label usada na criptografia, a chave privada adquirida em 2.1, e uma string com o nome do arquivo de saída. 

2 - Primeiro se busca o []byte referente a label e a função rsa.DecryptOAEP para descriptografar. A função pede:
hash => sha256.New()
random io.Reader => rand.Reader
chave privada => privKey adquirida em 1.1
[]byte da cifra => ciphertext adquirido em 2.2
[]byte da label
```
    label := []byte(labelname)
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, label)
	if err != nil {
		return fmt.Errorf("error on decrypting file from ciphertext: %s", err.Error())
	}
```

3 - Em seguida, cria-se o arquivo descriptografado usando os.Create(nome do arquivo)
```
    file, err := os.Create(decryptedFileName)
	if err != nil {
		return fmt.Errorf("error on creating decrypted file: %s", err.Error())
	}
```

4 - É escrito o conteúdo da descriptografia no file criado acima, usando file.Write(plaintext)
```
    _, err = file.Write(plaintext)
	if err != nil {
		return fmt.Errorf("error on writing in decrypted file: %s", err.Error())
	}
```
**OBS**:Arquivos em tests possuem exemplos completos realizando o passo a passo de criação de chave e criptografia e descriptografia.