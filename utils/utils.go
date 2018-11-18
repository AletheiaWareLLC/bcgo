/*
 * Copyright 2018 Aletheia Ware LLC
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
package utils

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha512"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "io/ioutil"
    "log"
    "math/bits"
    "os"
    "path"
)

const (
    AES_PRIMARY_KEY_SIZE = 32
    AES_SECONDARY_KEY_SIZE = 16
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
        Type:  "RSA PUBLIC KEY",
        Bytes: bytes,
    }, nil
}

func RSAPrivateKeyToPEM(privateKey *rsa.PrivateKey, password []byte) (*pem.Block, error) {
    // Create encrypted PEM block with private key marshalled into PKCS8
    data, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, err
    }
    return x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", data, password, x509.PEMCipherAES256)
}

func HasRSAPrivateKey(directory string) bool {
    _, err := os.Stat(path.Join(directory, "private.pem"))
    if err != nil {
        if os.IsNotExist(err) {
            return false
        }
    }
    return true
}

func CreateRSAPrivateKey(directory string, password []byte) (*rsa.PrivateKey, error) {
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

    // Encode Private Key to PEM block
    privateKeyPEM, err := RSAPrivateKeyToPEM(privateKey, password)
    if err != nil {
        return nil, err
    }

    // Write Private Key PEM block to file
    if err := WritePEM(privateKeyPEM, path.Join(directory, "private.pem")); err != nil {
        return nil, err
    }

    // Encode Public Key to PEM block
    publicKeyPEM, err := RSAPublicKeyToPEM(&privateKey.PublicKey)
    if err != nil {
        return nil, err
    }

    // Write Public Key PEM block to file
    if err := WritePEM(publicKeyPEM, path.Join(directory, "public.pem")); err != nil {
        return nil, err
    }

    return privateKey, nil
}

func GetRSAPrivateKey(directory string, password []byte) (*rsa.PrivateKey, error) {
    privateKeyPEM, err := ReadPEM(path.Join(directory, "private.pem"))
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
