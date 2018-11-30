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

package bcgo

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"github.com/AletheiaWareLLC/bcgo/utils"
	"github.com/golang/protobuf/proto"
	"io"
	"io/ioutil"
	"log"
	"path"
	"time"
)

const (
	THRESHOLD_NONE     = 0
	THRESHOLD_LITE     = 264 // 33/64
	THRESHOLD_STANDARD = 272 // 17/32
	THRESHOLD_PVB_HOUR = 288 // 9/16
	THRESHOLD_PVB_DAY  = 320 // 5/8
	THRESHOLD_PVB_YEAR = 384 // 3/4

	PORT_BLOCK  = 22222
	PORT_HEAD   = 22232
	PORT_KEYS   = 22322
	PORT_STATUS = 23222
	PORT_WRITE  = 23232
)

type Channel struct {
	Name      string
	Threshold uint64
	Head      *Block
	Cache     string
}

func (c *Channel) Update(hash []byte, block *Block) error {
	head := Reference{
		Timestamp:   block.Timestamp,
		ChannelName: c.Name,
		BlockHash:   hash,
	}
	if err := WriteHeadFile(c.Cache, c.Name, &head); err != nil {
		return err
	}
	c.Head = block
	return WriteBlockFile(c.Cache, hash, block)
}

func (c *Channel) LoadHead() error {
	head, err := ReadHeadFile(c.Cache, c.Name)
	if err != nil {
		return err
	}
	block, err := ReadBlockFile(c.Cache, head.BlockHash)
	if err != nil {
		return err
	}
	c.Head = block
	return nil
}

type Node struct {
	Key *rsa.PrivateKey
}

func (n *Node) Mine(channel *Channel, entries []*BlockEntry) ([]byte, *Block, error) {
	minerKeyBytes, err := utils.RSAPublicKeyToBytes(&n.Key.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	block := &Block{
		Timestamp:    uint64(time.Now().UnixNano()),
		ChannelName:  channel.Name,
		Length:       1,
		MinerKeyHash: utils.Hash(minerKeyBytes),
		Entry:        entries,
	}

	previous := channel.Head
	if previous != nil {
		block.Length = previous.Length + 1
		data, err := proto.Marshal(previous)
		if err != nil {
			return nil, nil, err
		}
		block.Previous = utils.Hash(data)
	}

	log.Println("Mining", channel.Name, proto.Size(block))

	var nonce uint64
	var max uint64
	for ; nonce >= 0; nonce++ {
		block.Nonce = nonce
		data, err := proto.Marshal(block)
		if err != nil {
			return nil, nil, err
		}
		hash := utils.Hash(data)
		ones := utils.Ones(hash)
		if ones > max {
			log.Println("Mining", channel.Name, nonce, ones, "/", (len(hash) * 8))
			max = ones
		}
		if ones > channel.Threshold {
			log.Println("Mined", channel.Name, block.Timestamp, base64.RawURLEncoding.EncodeToString(hash))
			err := channel.Update(hash, block)
			if err != nil {
				return nil, nil, err
			}
			return hash, block, nil
		}
	}
	return nil, nil, errors.New("Nonce wrapped around before reaching threshold")
}

func CreateMessage(sender *rsa.PrivateKey, recipients []*rsa.PublicKey, references []*Reference, payload []byte) (*Message, error) {
	// Generate a random shared key
	key := make([]byte, utils.AES_KEY_SIZE_BYTES)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

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
	encryptedPayload := append(nonce, gcm.Seal(nil, nonce, payload, nil)...)

	// Hash encrypted payload
	hashed := utils.Hash(encryptedPayload)

	// Sign hash of encrypted payload
	signature, err := CreateSignature(sender, hashed)
	if err != nil {
		return nil, err
	}

	// Grant access to each recipient
	recs := make([]*Message_Access, len(recipients))
	for i, k := range recipients {
		publicKeyBytes, err := utils.RSAPublicKeyToBytes(k)
		if err != nil {
			return nil, err
		}
		publicKeyHash := utils.Hash(publicKeyBytes)
		secretKey, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, k, key, nil)
		if err != nil {
			return nil, err
		}
		recs[i] = &Message_Access{
			PublicKeyHash: publicKeyHash,
			SecretKey:     secretKey,
		}
	}

	senderKeyBytes, err := utils.RSAPublicKeyToBytes(&sender.PublicKey)
	if err != nil {
		return nil, err
	}

	// Create message
	return &Message{
		Timestamp:     uint64(time.Now().UnixNano()),
		SenderKeyHash: utils.Hash(senderKeyBytes),
		Recipient:     recs,
		Payload:       encryptedPayload,
		Signature:     signature,
		Reference:     references,
	}, nil
}

func CreateSignature(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	var options rsa.PSSOptions
	options.SaltLength = rsa.PSSSaltLengthAuto
	return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, data, &options)
}

func VerifySignature(publicKey *rsa.PublicKey, data, signature []byte) error {
	var options rsa.PSSOptions
	options.SaltLength = rsa.PSSSaltLengthAuto
	err := rsa.VerifyPSS(publicKey, crypto.SHA512, data, signature, &options)
	if err != nil {
		return err
	}
	return nil
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

func ReadReference(reader io.Reader) (*Reference, error) {
	var data [1024]byte
	n, err := reader.Read(data[:])
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, errors.New("Could not read data")
	}
	size, s := proto.DecodeVarint(data[:])
	if s <= 0 {
		return nil, errors.New("Could not read size")
	}
	e := uint64(s) + size

	// Unmarshal as Reference
	request := &Reference{}
	if err = proto.Unmarshal(data[s:e], request); err != nil {
		return nil, err
	}
	return request, nil
}

func WriteBlock(writer io.Writer, block *Block) error {
	// Marshal to byte array
	data, err := proto.Marshal(block)
	if err != nil {
		return err
	}
	size := uint64(len(data))
	// Write block size varint
	if _, err := writer.Write(proto.EncodeVarint(size)); err != nil {
		return err
	}
	// Write block data
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return nil
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

func WriteReference(writer io.Writer, reference *Reference) error {
	// Marshal to byte array
	data, err := proto.Marshal(reference)
	if err != nil {
		return err
	}
	size := uint64(len(data))
	// Write reference size varint
	if _, err := writer.Write(proto.EncodeVarint(size)); err != nil {
		return err
	}
	// Write reference data
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return nil
}
