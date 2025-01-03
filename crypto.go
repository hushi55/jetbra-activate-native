package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	CAPath   = "/.config/jetbra-activate"
	KeyPath  = "/ca.key"
	CertPath = "/ca.crt"
)

const (
	JetKeySize    = 4096
	JetPrivateKey = "860106576952879101192782278876319243486072481962999610484027161162448933268423045647258145695082284265933019120714643752088997312766689988016808929265129401027490891810902278465065056686129972085119605237470899952751915070244375173428976413406363879128531449407795115913715863867259163957682164040613505040314747660800424242248055421184038777878268502955477482203711835548014501087778959157112423823275878824729132393281517778742463067583320091009916141454657614089600126948087954465055321987012989937065785013284988096504657892738536613208311013047138019418152103262155848541574327484510025594166239784429845180875774012229784878903603491426732347994359380330103328705981064044872334790365894924494923595382470094461546336020961505275530597716457288511366082299255537762891238136381924520749228412559219346777184174219999640906007205260040707839706131662149325151230558316068068139406816080119906833578907759960298749494098180107991752250725928647349597506532778539709852254478061194098069801549845163358315116260915270480057699929968468068015735162890213859113563672040630687357054902747438421559817252127187138838514773245413540030800888215961904267348727206110582505606182944023582459006406137831940959195566364811905585377246353"
)

var cryptoUtil *CryptoUtil

func init() {
	var err error

	home, err := os.UserHomeDir()
	CAPath = filepath.Join(home, CAPath)
	_ = os.MkdirAll(CAPath, os.ModePerm)

	KeyPath = filepath.Join(CAPath, KeyPath)
	CertPath = filepath.Join(CAPath, CertPath)

	cryptoUtil, err = NewCryptoUtil()
	if err != nil {
		panic(fmt.Errorf("签名工具初始化失败，err: %s", err.Error()))
	}
}

func EnsureKeyFile(keyPath string) (*rsa.PrivateKey, error) {
	keyRaw, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		privKey, _ := rsa.GenerateKey(rand.Reader, JetKeySize)

		keyRaw, _ = x509.MarshalPKCS8PrivateKey(privKey)
		err = saveToPemFile(keyPath, "PRIVATE KEY", keyRaw)
		return privKey, err
	}
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyRaw)
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey.(*rsa.PrivateKey), nil
}

func EnsureCertFile(certPath string, privKey *rsa.PrivateKey) (*x509.Certificate, error) {
	certRaw, err := os.ReadFile(certPath)
	if os.IsNotExist(err) {
		if privKey == nil {
			return nil, errors.New("privKey is nil, can't create crt")
		}

		cert, err := GenCert(privKey)
		if err != nil {
			return nil, err
		}

		err = saveToPemFile(certPath, "CERTIFICATE", cert.Raw)
		return cert, err
	}
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certRaw)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

// GenCert 生成证书
func GenCert(priv *rsa.PrivateKey) (*x509.Certificate, error) {
	serialNumber := big.NewInt(time.Now().Unix())
	notBefore := time.Now().Add(-time.Hour * 24 * 365)
	notAfter := time.Now().Add(time.Hour * 24 * 365 * 10)

	// 生成一份由 JetProfile CA 发布给本机的证书
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: GetLicenseName(),
		},
		Issuer: pkix.Name{
			CommonName: "JetProfile CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true, // Root certificate
	}

	// 证书需要指定父证书
	templateParent := template
	templateParent.Issuer = pkix.Name{}
	templateParent.Subject = pkix.Name{CommonName: "JetProfile CA"}

	certDER, err := x509.CreateCertificate(
		nil,
		&template,
		&templateParent,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)

	return cert, err
}

func saveToPemFile(filename, blockType string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	block := &pem.Block{
		Type:  blockType,
		Bytes: data,
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

type CryptoUtil struct {
	privKey *rsa.PrivateKey
	pubKey  *rsa.PublicKey
	cert    *x509.Certificate
}

func NewCryptoUtil() (*CryptoUtil, error) {
	privKey, err := EnsureKeyFile(KeyPath)
	if err != nil {
		return nil, err
	}

	cert, err := EnsureCertFile(CertPath, privKey)
	if err != nil {
		return nil, err
	}

	util := &CryptoUtil{
		privKey: privKey,
		pubKey:  &privKey.PublicKey,
		cert:    cert,
	}

	if !util.pubKey.Equal(cert.PublicKey) {
		return nil, errors.New("证书和密钥不匹配")
	}

	return util, nil
}

// GenPowerConf 生成 ja-netfilter 所需的 power.conf 配置
func (c CryptoUtil) GenPowerConf(confPath string) error {
	// 获取公钥的指数
	exponent := c.pubKey.E

	bytes, err := encodePowerConfSignature(c.cert.RawTBSCertificate, c.pubKey.N.BitLen())
	if err != nil {
		return err
	}

	// 创建 power.conf 配置内容
	powerConfig := fmt.Sprintf("[Result]\nEQUAL,%s,%d,%s->%s",
		new(big.Int).SetBytes(c.cert.Signature).String(),
		exponent,
		JetPrivateKey,
		new(big.Int).SetBytes(bytes).String(),
	)

	return os.WriteFile(confPath, []byte(powerConfig), 0644)
}

// sha256 摘要后编码成 ans1 格式，再按照 PKCS#1 v1.5 格式 padding
func encodePowerConfSignature(values []byte, keySize int) ([]byte, error) {
	if keySize%8 != 0 {
		return nil, fmt.Errorf("key size must be a multiple of 8")
	}

	hashed := sha256.Sum256(values)

	var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// Define the ASN.1 structures
	// go ans1 库没有相关结构体只能手建
	type pkcs1DigestInfo struct {
		Algorithm struct {
			OID  asn1.ObjectIdentifier
			Null asn1.RawValue // 显式添加 NULL 参数
		}
		Digest []byte
	}

	digestInfo := pkcs1DigestInfo{
		Algorithm: struct {
			OID  asn1.ObjectIdentifier
			Null asn1.RawValue
		}{
			OID:  oidSHA256,
			Null: asn1.RawValue{Tag: asn1.TagNull},
		},
		Digest: hashed[:],
	}

	asn1Bytes, err := asn1.Marshal(digestInfo)
	if err != nil {
		return nil, fmt.Errorf("asn1 marshal error: %w", err)
	}

	// PKCS#1 v1.5 padding
	padded := make([]byte, (keySize+7)/8)
	padded[1] = 0x01
	for i := 2; i < len(padded)-len(asn1Bytes)-1; i++ {
		padded[i] = 0xff
	}
	padded[len(padded)-len(asn1Bytes)-1] = 0x00
	copy(padded[len(padded)-len(asn1Bytes):], asn1Bytes)

	return padded, nil
}

// GenActivateCode 生成激活码
func (c CryptoUtil) GenActivateCode(licenseName, expireDate string, product ...Product) (string, error) {
	license := NewLicense(licenseName, expireDate, product...)
	licenseRaw := license.Raw()

	hashed := sha1.Sum(licenseRaw)

	signature, err := c.privKey.Sign(rand.Reader, hashed[:], crypto.SHA1)
	if err != nil {
		return "", err
	}

	err = rsa.VerifyPKCS1v15(c.pubKey, crypto.SHA1, hashed[:], signature)
	if err != nil {
		return "", errors.New("gen activate code verify failed")
	}

	code := fmt.Sprintf("%s-%s-%s-%s",
		license.LicenseID,
		base64.StdEncoding.EncodeToString(licenseRaw),
		base64.StdEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(c.cert.Raw),
	)

	return code, nil
}
