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
	"bufio"
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
	"math/bits"
	"os"
	"os/user"
	"path"
	"strings"
	"syscall"
	"time"
)

const (
	AES_KEY_SIZE_BITS  = 128
	AES_KEY_SIZE_BYTES = AES_KEY_SIZE_BITS / 8

	BC_HOST    = "bc.aletheiaware.com"
	BC_WEBSITE = "https://bc.aletheiaware.com"
)

func Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

func Ones(data []byte) uint64 {
	var count uint64
	for _, x := range data {
		count += uint64(bits.OnesCount(uint(x)))
	}
	return count
}

func RSAPublicKeyToBase64(publicKey *rsa.PublicKey) (string, error) {
	pub, err := RSAPublicKeyToBytes(publicKey)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

func RSAPublicKeyToBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func RSAPublicKeyFromBase64(publicKey string) (*rsa.PublicKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	return RSAPublicKeyFromBytes(data)
}

func RSAPublicKeyFromBytes(data []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	switch k := pub.(type) {
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
		// TODO
		return nil, errors.New("PKCS1 public key format not yet implemented")
	case PublicKeyFormat_PKIX:
		return RSAPublicKeyFromBytes(publicKey)
	case PublicKeyFormat_X509:
		// TODO
		return nil, errors.New("X509 public key format not yet implemented")
	case PublicKeyFormat_UNKNOWN_PUBLIC_KEY_FORMAT:
		fallthrough
	default:
		return nil, errors.New("Unsupported Public Key Format: " + format.String())
	}
}

func ParseRSAPrivateKey(privateKey []byte, format PrivateKeyFormat) (*rsa.PrivateKey, error) {
	switch format {
	case PrivateKeyFormat_PKCS1_PRIVATE:
		// TODO
		return nil, errors.New("PKCS1 private key format not yet implemented")
	case PrivateKeyFormat_PKCS8:
		priv, err := x509.ParsePKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		switch k := priv.(type) {
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, errors.New("Unsupported private key type")
		}
	case PrivateKeyFormat_UNKNOWN_PRIVATE_KEY_FORMAT:
		fallthrough
	default:
		return nil, errors.New("Unsupported Private Key Format: " + format.String())
	}
}

func HasRSAPrivateKey(directory, alias string) bool {
	_, err := os.Stat(path.Join(directory, alias+".priv"))
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func CreateRSAPrivateKey(directory, alias string, password []byte) (*rsa.PrivateKey, error) {
	// Create directory
	err := os.MkdirAll(directory, 0700)
	if err != nil {
		return nil, err
	}

	log.Println("Generating RSA-4096bit public/private key pair")
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
	if err := WritePEM(privateKeyPEM, path.Join(directory, alias+".priv")); err != nil {
		return err
	}

	return nil
}

func GetRSAPrivateKey(directory, alias string, password []byte) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := ReadPEM(path.Join(directory, alias+".priv"))
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

func GetKeyStore() (string, error) {
	keystore, ok := os.LookupEnv("KEYSTORE")
	if !ok {
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		keystore = path.Join(u.HomeDir, "bc")
	}
	return keystore, nil
}

func GetPassword() ([]byte, error) {
	pwd, ok := os.LookupEnv("PASSWORD")
	if ok {
		return []byte(pwd), nil
	} else {
		log.Print("Enter keystore password: ")
		password, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		log.Println()
		return password, nil
	}
}

func GetOrCreateRSAPrivateKey() (string, *rsa.PrivateKey, error) {
	keystore, err := GetKeyStore()
	if err != nil {
		return "", nil, err
	}

	alias, ok := os.LookupEnv("ALIAS")
	if !ok {
		u, err := user.Current()
		if err != nil {
			return "", nil, err
		}
		alias = u.Username
	}

	if HasRSAPrivateKey(keystore, alias) {
		log.Println("Found keystore under " + keystore + " for " + alias)
		password, err := GetPassword()
		if err != nil {
			return "", nil, err
		}
		key, err := GetRSAPrivateKey(keystore, alias, password)
		if err != nil {
			return "", nil, err
		}
		return alias, key, nil
	} else {
		log.Println("Creating keystore under " + keystore)

		log.Print("Enter keystore password: ")
		password, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", nil, err
		}
		log.Println()

		log.Print("Confirm keystore password: ")
		confirm, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", nil, err
		}
		log.Println()

		if !bytes.Equal(password, confirm) {
			log.Fatal("Passwords don't match")
		}

		key, err := CreateRSAPrivateKey(keystore, alias, password)
		if err != nil {
			return "", nil, err
		}

		publicKeyBase64, err := RSAPublicKeyToBase64(&key.PublicKey)
		if err != nil {
			return "", nil, err
		}
		log.Printf("Successfully created key pair, visit %s/register and register your public key;\n%s\n\n", BC_HOST, publicKeyBase64)
		return alias, key, nil
	}
}

func GetHosts() ([]string, error) {
	env, ok := os.LookupEnv("HOSTS")
	if ok {
		return strings.Split(string(env), ","), nil
	} else {
		u, err := user.Current()
		if err != nil {
			return nil, err
		}

		data, err := ioutil.ReadFile(path.Join(u.HomeDir, "bc/hosts"))
		if err != nil {
			return nil, err
		}

		return strings.Split(string(data), "\n"), nil
	}
}

func AddHost(host string) error {
	hosts, err := GetHosts()
	if err != nil {
		return err
	}

	u, err := user.Current()
	if err != nil {
		return err
	}
	filename := path.Join(u.HomeDir, "bc/hosts")
	content := strings.Join(append(hosts, host), "\n")
	ioutil.WriteFile(filename, []byte(content), 0600)
	return nil
}

func GetCache() (string, error) {
	cache, ok := os.LookupEnv("CACHE")
	if !ok {
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		cache = path.Join(u.HomeDir, "bc")
	}
	return cache, nil
}

func DecryptRecord(entry *BlockEntry, access *Record_Access, key *rsa.PrivateKey, callback func(*BlockEntry, []byte)) error {
	record := entry.Record
	switch access.EncryptionAlgorithm {
	case EncryptionAlgorithm_RSA_ECB_OAEPPADDING:
		// Decrypt a shared key
		decryptedKey, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, key, access.SecretKey, nil)
		if err != nil {
			return err
		}
		switch record.EncryptionAlgorithm {
		case EncryptionAlgorithm_AES_GCM_NOPADDING:
			decryptedPayload, err := DecryptAESGCM(decryptedKey, record.Payload)
			if err != nil {
				return err
			}
			// Call callback
			callback(entry, decryptedPayload)
		case EncryptionAlgorithm_UNKNOWN_ENCRYPTION:
			fallthrough
		default:
		}
	case EncryptionAlgorithm_UNKNOWN_ENCRYPTION:
		fallthrough
	default:
		// Call callback
		callback(entry, record.Payload)
	}
	return nil
}

func CreateRecord(creatorAlias string, creatorKey *rsa.PrivateKey, access map[string]*rsa.PublicKey, references []*Reference, payload []byte) (*Record, error) {
	key, err := GenerateRandomKey()
	if err != nil {
		return nil, err
	}

	encrypted, err := EncryptAESGCM(key, payload)
	if err != nil {
		return nil, err
	}

	// Hash encrypted payload
	hashed := Hash(encrypted)

	// Sign hash of encrypted payload
	signature, err := CreateSignature(creatorKey, hashed, SignatureAlgorithm_SHA512WITHRSA_PSS)
	if err != nil {
		return nil, err
	}

	// Grant access to each public key
	acl := make([]*Record_Access, 0)
	for a, k := range access {
		secretKey, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, k, key, nil)
		if err != nil {
			return nil, err
		}
		acl = append(acl, &Record_Access{
			Alias:               a,
			SecretKey:           secretKey,
			EncryptionAlgorithm: EncryptionAlgorithm_RSA_ECB_OAEPPADDING,
		})
	}

	// Create record
	return &Record{
		Timestamp:           uint64(time.Now().UnixNano()),
		Creator:             creatorAlias,
		Access:              acl,
		Payload:             encrypted,
		EncryptionAlgorithm: EncryptionAlgorithm_AES_GCM_NOPADDING,
		Signature:           signature,
		SignatureAlgorithm:  SignatureAlgorithm_SHA512WITHRSA_PSS,
		Reference:           references,
	}, nil
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

func PrintBlock(hash []byte, block *Block) {
	log.Println("Hash:", base64.RawURLEncoding.EncodeToString(hash))
	log.Println("Timestamp:", block.Timestamp)
	log.Println("ChannelName:", block.ChannelName)
	log.Println("Length:", block.Length)
	log.Println("Previous:", base64.RawURLEncoding.EncodeToString(block.Previous))
	log.Println("Miner:", block.Miner)
	log.Println("Nonce:", block.Nonce)
	log.Println("Entries:", len(block.Entry))
	for i, entry := range block.Entry {
		log.Println("Entry:", i)
		log.Println("Hash:", base64.RawURLEncoding.EncodeToString(entry.RecordHash))
		log.Println("Timestamp:", entry.Record.Timestamp)
		log.Println("Creator:", entry.Record.Creator)
		for j, access := range entry.Record.Access {
			log.Println("Access:", j)
			log.Println("Alias:", access.Alias)
			log.Println("SecretKey:", base64.RawURLEncoding.EncodeToString(access.SecretKey))
			log.Println("KeyEncryptionAlgorithm:", access.EncryptionAlgorithm)
		}
		log.Println("Payload:", base64.RawURLEncoding.EncodeToString(entry.Record.Payload))
		log.Println("CompressionAlgorithm:", entry.Record.CompressionAlgorithm)
		log.Println("EncryptionAlgorithm:", entry.Record.EncryptionAlgorithm)
		log.Println("Signature:", base64.RawURLEncoding.EncodeToString(entry.Record.Signature))
		log.Println("SignatureAlgorithm:", entry.Record.SignatureAlgorithm)
		for k, reference := range entry.Record.Reference {
			log.Println("Reference:", k)
			log.Println("Timestamp:", reference.Timestamp)
			log.Println("ChannelName:", reference.ChannelName)
			log.Println("BlockHash:", reference.BlockHash)
			log.Println("RecordHash:", reference.RecordHash)
		}
	}
}

func ReadBlock(reader *bufio.Reader) (*Block, error) {
	block := &Block{}
	if err := ReadDelimitedProtobuf(reader, block); err != nil {
		return nil, err
	}
	return block, nil
}

func ReadBlockFile(directory string, hash []byte) (*Block, error) {
	// Read from file
	data, err := ioutil.ReadFile(path.Join(directory, "block", base64.RawURLEncoding.EncodeToString(hash)))
	if err != nil {
		return nil, err
	}
	// Unmarshal into block
	block := &Block{}
	if err = proto.Unmarshal(data[:], block); err != nil {
		return nil, err
	}
	return block, err
}

func ReadHeadFile(directory, channel string) (*Reference, error) {
	// Read from file
	data, err := ioutil.ReadFile(path.Join(directory, "channel", base64.RawURLEncoding.EncodeToString([]byte(channel))))
	if err != nil {
		return nil, err
	}
	// Unmarshal into reference
	reference := &Reference{}
	if err = proto.Unmarshal(data[:], reference); err != nil {
		return nil, err
	}
	return reference, err
}

func ReadReference(reader *bufio.Reader) (*Reference, error) {
	reference := &Reference{}
	if err := ReadDelimitedProtobuf(reader, reference); err != nil {
		return nil, err
	}
	return reference, nil
}

func ReadDelimitedProtobuf(reader *bufio.Reader, destination proto.Message) error {
	var data [1024]byte
	n, err := reader.Read(data[:])
	if err != nil {
		return err
	}
	if n <= 0 {
		return errors.New("Could not read data")
	}
	size, s := proto.DecodeVarint(data[:])
	if s <= 0 {
		return errors.New("Could not read size")
	}

	// Create new larger buffer
	buffer := make([]byte, size)
	// Calculate data received
	count := uint64(n - s)
	// Copy data into new buffer
	copy(buffer[:count], data[s:n])
	// Read addition bytes
	for count < size {
		n, err := reader.Read(buffer[count:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Could not read data")
		}
		count = count + uint64(n)
	}

	if err = proto.Unmarshal(buffer, destination); err != nil {
		return err
	}
	return nil
}

func WriteBlock(writer *bufio.Writer, block *Block) error {
	return WriteDelimitedProtobuf(writer, block)
}

func WriteBlockFile(directory string, hash []byte, block *Block) error {
	// Marshal into byte array
	data, err := proto.Marshal(block)
	if err != nil {
		return err
	}
	// Write to file
	return ioutil.WriteFile(path.Join(directory, "block", base64.RawURLEncoding.EncodeToString(hash)), data, 0600)
}

func WriteHeadFile(directory, channel string, reference *Reference) error {
	// Marshal into byte array
	data, err := proto.Marshal(reference)
	if err != nil {
		return err
	}
	// Write to file
	return ioutil.WriteFile(path.Join(directory, "channel", base64.RawURLEncoding.EncodeToString([]byte(channel))), data, 0600)
}

func WriteReference(writer *bufio.Writer, reference *Reference) error {
	return WriteDelimitedProtobuf(writer, reference)
}

func WriteDelimitedProtobuf(writer *bufio.Writer, source proto.Message) error {
	data, err := proto.Marshal(source)
	if err != nil {
		return err
	}
	size := uint64(len(data))
	// Write request size varint
	if _, err := writer.Write(proto.EncodeVarint(size)); err != nil {
		return err
	}
	// Write request data
	if _, err = writer.Write(data); err != nil {
		return err
	}
	// Flush writer
	return writer.Flush()
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
	return ioutil.WriteFile(filename, pem.EncodeToMemory(key), 0600)
}
