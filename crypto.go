/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package containing utilities for BC in Go
package bcgo

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"syscall"
)

const (
	AES_KEY_SIZE_BITS  = 128
	AES_KEY_SIZE_BYTES = AES_KEY_SIZE_BITS / 8
)

func RSAPublicKeyToPKCS1Bytes(publicKey *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(publicKey)
}

func RSAPublicKeyToPKIXBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func RSAPublicKeyFromPKCS1Bytes(data []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKCS1PublicKey(data)
	if err != nil {
		return nil, err
	}
	return PublicKeyToRSAPublicKey(pub)
}

func RSAPublicKeyFromPKIXBytes(data []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}
	return PublicKeyToRSAPublicKey(pub)
}

func PublicKeyToRSAPublicKey(key interface{}) (*rsa.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, nil
	default:
		return nil, errors.New("Unsupported public key type")
	}
}

func RSAPublicKeyToPEM(publicKey *rsa.PublicKey) (*pem.Block, error) {
	// Marshal public key into PKIX
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	// Create PEM block
	return &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}, nil
}

func RSAPrivateKeyToPKCS1Bytes(privateKey *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(privateKey)
}

func RSAPrivateKeyToPKCS8Bytes(privateKey *rsa.PrivateKey) ([]byte, error) {
	bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func RSAPrivateKeyFromPKCS1Bytes(data []byte) (*rsa.PrivateKey, error) {
	priv, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		return nil, err
	}
	return PrivateKeyToRSAPrivateKey(priv)
}

func RSAPrivateKeyFromPKCS8Bytes(data []byte) (*rsa.PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, err
	}
	return PrivateKeyToRSAPrivateKey(priv)
}

func PrivateKeyToRSAPrivateKey(key interface{}) (*rsa.PrivateKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, errors.New("Unsupported private key type")
	}
}

func RSAPrivateKeyToPEM(privateKey *rsa.PrivateKey, password []byte) (*pem.Block, error) {
	// Create encrypted PEM block with private key marshalled into PKCS8
	data, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", data, password, x509.PEMCipherAES128)
}

func ParseRSAPublicKey(publicKey []byte, format PublicKeyFormat) (*rsa.PublicKey, error) {
	switch format {
	case PublicKeyFormat_PKCS1_PUBLIC:
		return RSAPublicKeyFromPKCS1Bytes(publicKey)
	case PublicKeyFormat_PKIX:
		fallthrough
	case PublicKeyFormat_X509:
		return RSAPublicKeyFromPKIXBytes(publicKey)
	case PublicKeyFormat_UNKNOWN_PUBLIC_KEY_FORMAT:
		fallthrough
	default:
		return nil, errors.New("Unsupported Public Key Format: " + format.String())
	}
}

func ParseRSAPrivateKey(privateKey []byte, format PrivateKeyFormat) (*rsa.PrivateKey, error) {
	switch format {
	case PrivateKeyFormat_PKCS1_PRIVATE:
		return RSAPrivateKeyFromPKCS1Bytes(privateKey)
	case PrivateKeyFormat_PKCS8:
		return RSAPrivateKeyFromPKCS8Bytes(privateKey)
	case PrivateKeyFormat_UNKNOWN_PRIVATE_KEY_FORMAT:
		fallthrough
	default:
		return nil, errors.New("Unsupported Private Key Format: " + format.String())
	}
}

func HasRSAPrivateKey(directory, alias string) bool {
	_, err := os.Stat(path.Join(directory, alias+".go.private"))
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func CreateRSAPrivateKey(directory, alias string, password []byte) (*rsa.PrivateKey, error) {
	// Create directory
	if err := os.MkdirAll(directory, os.ModePerm); err != nil {
		return nil, err
	}

	log.Println("Generating RSA-4096bit Public/Private Key Pair")
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	if err := WriteRSAPrivateKey(privateKey, directory, alias, password); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func WriteRSAPrivateKey(privateKey *rsa.PrivateKey, directory, alias string, password []byte) error {
	// Encode Private Key to PEM block
	privateKeyPEM, err := RSAPrivateKeyToPEM(privateKey, password)
	if err != nil {
		return err
	}

	// Write Private Key PEM block to file
	if err := WritePEM(privateKeyPEM, path.Join(directory, alias+".go.private")); err != nil {
		return err
	}

	return nil
}

func GetRSAPrivateKey(directory, alias string, password []byte) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := ReadPEM(path.Join(directory, alias+".go.private"))
	if err != nil {
		return nil, err
	}

	decrypted, err := x509.DecryptPEMBlock(privateKeyPEM, password)
	if err != nil {
		return nil, err
	}

	priv, err := x509.ParsePKCS8PrivateKey(decrypted)
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, errors.New("Unsupported private key type")
	}
}

func GetOrCreateRSAPrivateKey(directory, alias string) (*rsa.PrivateKey, error) {
	keystore, err := GetKeyDirectory(directory)
	if err != nil {
		return nil, err
	}

	if HasRSAPrivateKey(keystore, alias) {
		log.Println("Found keystore under " + keystore + " for " + alias)
		password, err := GetPassword()
		if err != nil {
			return nil, err
		}
		key, err := GetRSAPrivateKey(keystore, alias, password)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		log.Println("Creating keystore under " + keystore + " for " + alias)

		password, err := GetPassword()
		if err != nil {
			return nil, err
		}

		log.Print("Confirm keystore password: ")
		confirm, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		log.Println()

		if !bytes.Equal(password, confirm) {
			log.Fatal("Passwords don't match")
		}

		key, err := CreateRSAPrivateKey(keystore, alias, password)
		if err != nil {
			return nil, err
		}

		log.Println("Successfully Created Key Pair")
		return key, nil
	}
}

func ExportKeys(host, keystore, alias string, password []byte) (string, error) {
	privateKey, err := GetRSAPrivateKey(keystore, alias, password)
	if err != nil {
		return "", err
	}

	// Generate a random access code
	accessCode, err := GenerateRandomKey()
	if err != nil {
		return "", err
	}

	data, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	encryptedPrivateKeyBytes, err := EncryptAESGCM(accessCode, data)
	if err != nil {
		return "", err
	}
	publicKeyBytes, err := RSAPublicKeyToPKIXBytes(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	encryptedPassword, err := EncryptAESGCM(accessCode, password)
	if err != nil {
		return "", err
	}
	response, err := http.PostForm(host+"/keys", url.Values{
		"alias":            {alias},
		"publicKey":        {base64.RawURLEncoding.EncodeToString(publicKeyBytes)},
		"publicKeyFormat":  {"PKIX"},
		"privateKey":       {base64.RawURLEncoding.EncodeToString(encryptedPrivateKeyBytes)},
		"privateKeyFormat": {"PKCS8"},
		"password":         {base64.RawURLEncoding.EncodeToString(encryptedPassword)},
	})
	if err != nil {
		return "", err
	}
	switch response.StatusCode {
	case http.StatusOK:
		log.Println("Keys exported")
		return base64.RawURLEncoding.EncodeToString(accessCode), nil
	default:
		return "", errors.New("Export status: " + response.Status)
	}
}

func ImportKeys(host, keystore, alias, accessCode string) error {
	response, err := http.Get(host + "/keys?alias=" + alias)
	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	keyShare := &KeyShare{}
	if err = proto.Unmarshal(data, keyShare); err != nil {
		return err
	}
	if keyShare.Alias != alias {
		return errors.New("Incorrect KeyShare Alias")
	}
	// Decode Access Code
	decodedAccessCode, err := base64.RawURLEncoding.DecodeString(accessCode)
	if err != nil {
		return err
	}
	// Decrypt Private Key
	decryptedPrivateKey, err := DecryptAESGCM(decodedAccessCode, keyShare.PrivateKey)
	if err != nil {
		return err
	}
	// Parse Private Key
	privateKey, err := ParseRSAPrivateKey(decryptedPrivateKey, keyShare.PrivateFormat)
	if err != nil {
		return err
	}
	// Decrypt Password
	decryptedPassword, err := DecryptAESGCM(decodedAccessCode, keyShare.Password)
	if err != nil {
		return err
	}
	// Write Private Key
	if err := WriteRSAPrivateKey(privateKey, keystore, alias, decryptedPassword); err != nil {
		return err
	}
	log.Println("Keys imported")
	return nil
}

func DecryptRecord(entry *BlockEntry, access *Record_Access, key *rsa.PrivateKey, callback func(*BlockEntry, []byte, []byte) error) error {
	decryptedKey, err := DecryptKey(access, key)
	if err != nil {
		return err
	}
	record := entry.Record
	switch record.EncryptionAlgorithm {
	case EncryptionAlgorithm_AES_GCM_NOPADDING:
		decryptedPayload, err := DecryptAESGCM(decryptedKey, record.Payload)
		if err != nil {
			return err
		}
		// Call callback
		return callback(entry, decryptedKey, decryptedPayload)
	case EncryptionAlgorithm_UNKNOWN_ENCRYPTION:
		return callback(entry, nil, record.Payload)
	default:
		return errors.New("Unsupported encryption: " + record.EncryptionAlgorithm.String())
	}
}

func DecryptKey(access *Record_Access, key *rsa.PrivateKey) ([]byte, error) {
	switch access.EncryptionAlgorithm {
	case EncryptionAlgorithm_RSA_ECB_OAEPPADDING:
		// Decrypt a shared key
		return rsa.DecryptOAEP(sha512.New(), rand.Reader, key, access.SecretKey, nil)
	case EncryptionAlgorithm_UNKNOWN_ENCRYPTION:
		return access.SecretKey, nil
	default:
		return nil, errors.New("Unsupported encryption" + access.EncryptionAlgorithm.String())
	}
}

func DecryptPayload(entry *BlockEntry, key []byte) ([]byte, error) {
	switch entry.Record.EncryptionAlgorithm {
	case EncryptionAlgorithm_AES_GCM_NOPADDING:
		return DecryptAESGCM(key, entry.Record.Payload)
	case EncryptionAlgorithm_UNKNOWN_ENCRYPTION:
		return entry.Record.Payload, nil
	default:
		return nil, errors.New("Unsupported encryption: " + entry.Record.EncryptionAlgorithm.String())
	}
}

func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, AES_KEY_SIZE_BYTES)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func EncryptAESGCM(key, payload []byte) ([]byte, error) {
	// Create cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create galois counter mode
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt payload
	encrypted := append(nonce, gcm.Seal(nil, nonce, payload, nil)...)

	return encrypted, nil
}

func DecryptAESGCM(key, encrypted []byte) ([]byte, error) {
	// Create cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create galois counter mode
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Get nonce
	nonce := encrypted[:gcm.NonceSize()]
	// Get payload
	payload := encrypted[gcm.NonceSize():]

	// Decrypt payload
	return gcm.Open(nil, nonce, payload, nil)
}

func CreateSignature(privateKey *rsa.PrivateKey, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	switch algorithm {
	case SignatureAlgorithm_SHA512WITHRSA:
		return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, data)
	case SignatureAlgorithm_SHA512WITHRSA_PSS:
		var options rsa.PSSOptions
		options.SaltLength = rsa.PSSSaltLengthAuto
		return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, data, &options)
	case SignatureAlgorithm_UNKNOWN_SIGNATURE:
		fallthrough
	default:
		return nil, errors.New("Unknown Signature")
	}
}

func VerifySignature(publicKey *rsa.PublicKey, data, signature []byte, algorithm SignatureAlgorithm) error {
	switch algorithm {
	case SignatureAlgorithm_SHA512WITHRSA:
		return rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, data, signature)
	case SignatureAlgorithm_SHA512WITHRSA_PSS:
		var options rsa.PSSOptions
		options.SaltLength = rsa.PSSSaltLengthAuto
		return rsa.VerifyPSS(publicKey, crypto.SHA512, data, signature, &options)
	case SignatureAlgorithm_UNKNOWN_SIGNATURE:
		fallthrough
	default:
		return errors.New("Unknown Signature")
	}
}

func ReadPEM(filename string) (*pem.Block, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	return block, nil
}

func WritePEM(key *pem.Block, filename string) error {
	return ioutil.WriteFile(filename, pem.EncodeToMemory(key), os.ModePerm)
}
