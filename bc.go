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
	"errors"
	"github.com/AletheiaWareLLC/bcgo/utils"
	"github.com/golang/protobuf/proto"
	"io"
	"log"
	"time"
)

const (
	THRESHOLD_NONE     = 0
	THRESHOLD_LITE     = 264 // 33/64
	THRESHOLD_STANDARD = 272 // 17/32
	THRESHOLD_PVB_HOUR = 288 // 9/16
	THRESHOLD_PVB_DAY  = 320 // 5/8
	THRESHOLD_PVB_YEAR = 384 // 3/4
)

type Channel struct {
	Name      string
	Threshold uint64
	Head      *Block
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
			log.Println("Mining: ", nonce, ": ", ones, "/", (len(hash) * 8))
			max = ones
		}
		if ones > channel.Threshold {
			return hash, block, nil
		}
	}
	return nil, nil, errors.New("Nonce wrapped around before reaching threshold")
}

func CreateMessage(sender *rsa.PrivateKey, recipients []*rsa.PublicKey, references []*Reference, payload []byte) (*Message, error) {
	// Generate a random shared key
	key := make([]byte, utils.AES_PRIMARY_KEY_SIZE)
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
	encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

	// Hash encrypted payload
	hashed := utils.Hash(encryptedPayload)

	// Sign hash of encrypted payload
	var options rsa.PSSOptions
	options.SaltLength = rsa.PSSSaltLengthAuto
	signature, err := rsa.SignPSS(rand.Reader, sender, crypto.SHA512, hashed, &options)
	if err != nil {
		return nil, err
	}

	/*
	Verify Signature
	var options rsa.PSSOptions
	options.SaltLength = rsa.PSSSaltLengthAuto
	err = rsa.VerifyPSS(&priv.PublicKey, crypto.SHA512, hashed[:], signature, &options)
	if err != nil {
		return nil, err
	}
	*/

	// Grant access to each recipient
	recs := make([]*Message_Access, len(recipients))
	for i, k := range recipients {
		publicKeyBytes, err := utils.RSAPublicKeyToBytes(k)
		if err != nil {
			return nil, err
		}
		secretKey, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, k, key, nil)
		if err != nil {
			return nil, err
		}
		recs[i] = &Message_Access{
			PublicKeyHash: utils.Hash(publicKeyBytes),
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
