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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"log"
	"math/bits"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	BC_HOST      = "bc.aletheiaware.com"
	BC_HOST_TEST = "test-bc.aletheiaware.com"
)

func Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

func HashProtobuf(protobuf proto.Message) ([]byte, error) {
	data, err := proto.Marshal(protobuf)
	if err != nil {
		return nil, err
	}
	return Hash(data), nil
}

func Ones(data []byte) uint64 {
	var count uint64
	for _, x := range data {
		count += uint64(bits.OnesCount(uint(x)))
	}
	return count
}

func SizeToString(size uint64) string {
	if size <= 1024 {
		return fmt.Sprintf("%dbytes", size)
	}
	var unit string
	s := float64(size)
	if s >= 1024 {
		s = s / 1024
		unit = "Kb"
	}
	if s >= 1024 {
		s = s / 1024
		unit = "Mb"
	}
	if s >= 1024 {
		s = s / 1024
		unit = "Gb"
	}
	if s >= 1024 {
		s = s / 1024
		unit = "Tb"
	}
	if s >= 1024 {
		s = s / 1024
		unit = "Pb"
	}
	return fmt.Sprintf("%.2f%s", s, unit)
}

func TimestampToString(timestamp uint64) string {
	return time.Unix(0, int64(timestamp)).Format("2006-01-02 15:04:05")
}

func IsDebug() bool {
	debug, ok := os.LookupEnv("DEBUG")
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(debug)
	if err != nil {
		return false
	}
	return b
}

func GetBCHost() string {
	if IsDebug() {
		return BC_HOST_TEST
	}
	return BC_HOST
}

func GetBCWebsite() string {
	return "https://" + GetBCHost()
}

func GetAlias() (string, error) {
	alias, ok := os.LookupEnv("ALIAS")
	if !ok {
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		alias = u.Username
	}
	return alias, nil
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

func GetRootDirectory() (string, error) {
	root, ok := os.LookupEnv("ROOT_DIRECTORY")
	if !ok {
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		root = path.Join(u.HomeDir, "bc")
	}
	return root, nil
}

func GetKeyDirectory(directory string) (string, error) {
	keystore, ok := os.LookupEnv("KEYS_DIRECTORY")
	if !ok {
		keystore = path.Join(directory, "keys")
	}
	if err := os.MkdirAll(keystore, os.ModePerm); err != nil {
		return "", err
	}
	return keystore, nil
}

func GetCacheDirectory(directory string) (string, error) {
	cache, ok := os.LookupEnv("CACHE_DIRECTORY")
	if !ok {
		cache = path.Join(directory, "cache")
	}
	return cache, nil
}

func GetCertificateDirectory(directory string) (string, error) {
	certs, ok := os.LookupEnv("CERTIFICATE_DIRECTORY")
	if !ok {
		certs = path.Join(directory, "certificates")
	}
	return certs, nil
}

func SetupLogging(directory string) (*os.File, error) {
	store, ok := os.LookupEnv("LOG_DIRECTORY")
	if !ok {
		store = path.Join(directory, "bc", "logs")
	}
	if err := os.MkdirAll(store, os.ModePerm); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(path.Join(store, time.Now().Format(time.RFC3339)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	return logFile, nil
}

func GetPeers(directory string) ([]string, error) {
	env, ok := os.LookupEnv("PEERS")
	if ok {
		return strings.Split(string(env), ","), nil
	} else {
		data, err := ioutil.ReadFile(path.Join(directory, "peers"))
		if err != nil {
			return nil, err
		}

		return strings.Split(string(data), "\n"), nil
	}
}

func AddPeer(directory, peer string) error {
	file, err := os.OpenFile(path.Join(directory, "peers"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(peer + "\n"); err != nil {
		return err
	}
	return nil
}

// Chunk the data from reader into individual records with their own secret key and access list
func CreateRecords(creatorAlias string, creatorKey *rsa.PrivateKey, access map[string]*rsa.PublicKey, references []*Reference, reader io.Reader, callback func([]byte, *Record) error) (int, error) {
	payload := make([]byte, MAX_PAYLOAD_SIZE_BYTES)
	size := 0
	for {
		count, err := reader.Read(payload)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}
		size = size + count
		key, record, err := CreateRecord(creatorAlias, creatorKey, access, references, payload[:count])
		if err != nil {
			return 0, err
		}
		if err := callback(key, record); err != nil {
			return 0, err
		}
	}
	return size, nil
}

func CreateRecord(creatorAlias string, creatorKey *rsa.PrivateKey, access map[string]*rsa.PublicKey, references []*Reference, payload []byte) ([]byte, *Record, error) {
	size := uint64(len(payload))
	if size > MAX_PAYLOAD_SIZE_BYTES {
		return nil, nil, errors.New("Payload too large: " + SizeToString(size) + " max: " + SizeToString(MAX_PAYLOAD_SIZE_BYTES))
	}
	acl := make([]*Record_Access, 0, len(access))
	var key []byte
	var err error
	if len(access) > 0 {
		key, err = GenerateRandomKey()
		if err != nil {
			return nil, nil, err
		}

		payload, err = EncryptAESGCM(key, payload)
		if err != nil {
			return nil, nil, err
		}

		// Grant access to each public key
		for a, k := range access {
			secretKey, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, k, key, nil)
			if err != nil {
				return nil, nil, err
			}
			acl = append(acl, &Record_Access{
				Alias:               a,
				SecretKey:           secretKey,
				EncryptionAlgorithm: EncryptionAlgorithm_RSA_ECB_OAEPPADDING,
			})
		}
	} else {
		log.Println("No aliases granted access, creating public record")
	}

	// Hash payload
	hashed := Hash(payload)

	// Sign hash of encrypted payload
	signature, err := CreateSignature(creatorKey, hashed, SignatureAlgorithm_SHA512WITHRSA_PSS)
	if err != nil {
		return nil, nil, err
	}

	// Create record
	record := &Record{
		Timestamp:           uint64(time.Now().UnixNano()),
		Creator:             creatorAlias,
		Payload:             payload,
		EncryptionAlgorithm: EncryptionAlgorithm_AES_GCM_NOPADDING,
		Signature:           signature,
		SignatureAlgorithm:  SignatureAlgorithm_SHA512WITHRSA_PSS,
		Reference:           references,
	}
	if acl != nil && len(acl) > 0 {
		record.Access = acl
	}
	return key, record, nil
}

func ReadDelimitedProtobuf(reader *bufio.Reader, destination proto.Message) error {
	data := make([]byte, 32)
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
	if size > MAX_BLOCK_SIZE_BYTES {
		return errors.New(fmt.Sprintf("Protobuf too large: %d max: %d", size, MAX_BLOCK_SIZE_BYTES))
	}

	// Calculate data received
	count := uint64(n - s)
	log.Println("n", n, "size", size, "s", s, "count", count)
	if count >= size {
		// All data in data[s:n]
		if err = proto.Unmarshal(data[s:s+int(size)], destination); err != nil {
			return err
		}
	} else {
		// More data in reader
		// Create new larger buffer
		buffer := make([]byte, size)
		// Copy data into new buffer
		copy(buffer[:count], data[s:n])
		// Read addition bytes
		for count < size {
			n, err := reader.Read(buffer[count:])
			if err != nil {
				if err == io.EOF {
					// Ignore EOFs, keep trying to read until count == size
					log.Println(err)
				} else {
					return err
				}
			}
			if n <= 0 {
				return errors.New("Could not read data")
			}
			count = count + uint64(n)
		}

		if err = proto.Unmarshal(buffer, destination); err != nil {
			return err
		}
	}
	return nil
}

func WriteDelimitedProtobuf(writer *bufio.Writer, source proto.Message) error {
	size := uint64(proto.Size(source))
	if size > MAX_BLOCK_SIZE_BYTES {
		return errors.New("Protobuf too large: " + SizeToString(size) + " max: " + SizeToString(MAX_BLOCK_SIZE_BYTES))
	}

	data, err := proto.Marshal(source)
	if err != nil {
		return err
	}
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
