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

package bcgo

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	ERROR_CHAIN_INVALID   = "Chain invalid: %s"
	ERROR_CHAIN_TOO_SHORT = "Chain too short to replace current head: %d vs %d"
	ERROR_HASH_INCORRECT  = "Hash doesn't match block hash"
)

type Channel interface {
	fmt.Stringer
	GetName() string
	GetHead() []byte
	SetHead([]byte)
	GetTimestamp() uint64
	SetTimestamp(uint64)
	Validate(cache Cache, hash []byte, block *Block) error
}

func Update(channel Channel, cache Cache, hash []byte, block *Block) error {
	head := channel.GetHead()
	if bytes.Equal(head, hash) {
		// Channel up to date
		return nil
	}

	// Check hash matches block hash
	h, err := HashProtobuf(block)
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, h) {
		return errors.New(ERROR_HASH_INCORRECT)
	}
	if head != nil {
		b, err := cache.GetBlock(head)
		if err != nil {
			return err
		}
		// Check block chain is longer than current head
		if b != nil && b.Length >= block.Length {
			return errors.New(fmt.Sprintf(ERROR_CHAIN_TOO_SHORT, block.Length, b.Length))
		}
	}

	if err := channel.Validate(cache, hash, block); err != nil {
		return errors.New(fmt.Sprintf(ERROR_CHAIN_INVALID, err.Error()))
	}

	channel.SetTimestamp(block.Timestamp)
	channel.SetHead(hash)
	fmt.Printf("%s updated to %s %s\n", channel.GetName(), TimestampToString(block.Timestamp), base64.RawURLEncoding.EncodeToString(hash))
	if err := cache.PutHead(channel.GetName(), &Reference{
		Timestamp:   block.Timestamp,
		ChannelName: channel.GetName(),
		BlockHash:   hash,
	}); err != nil {
		return err
	}
	return cache.PutBlock(hash, block)
}

func ReadKey(hash []byte, block *Block, cache Cache, alias string, key *rsa.PrivateKey, recordHash []byte, callback func([]byte) error) error {
	return Iterate(hash, block, cache, func(h []byte, b *Block) error {
		for _, entry := range block.Entry {
			if bytes.Equal(recordHash, entry.RecordHash) {
				for _, access := range entry.Record.Access {
					if alias == "" || alias == access.Alias {
						decryptedKey, err := DecryptKey(access, key)
						if err != nil {
							return err
						}
						return callback(decryptedKey)
					}
				}
			}
		}
		return nil
	})
}

func Read(hash []byte, block *Block, cache Cache, alias string, key *rsa.PrivateKey, recordHash []byte, callback func(*BlockEntry, []byte, []byte) error) error {
	// Decrypt each record in chain and pass to the given callback
	return Iterate(hash, block, cache, func(h []byte, b *Block) error {
		for _, entry := range b.Entry {
			if recordHash == nil || bytes.Equal(recordHash, entry.RecordHash) {
				if len(entry.Record.Access) == 0 {
					// No Access Declared - Data is public and unencrypted
					if err := callback(entry, nil, entry.Record.Payload); err != nil {
						return err
					}
				} else {
					for _, access := range entry.Record.Access {
						if alias == "" || alias == access.Alias {
							if err := DecryptRecord(entry, access, key, callback); err != nil {
								return err
							}
						}
					}
				}
			}
		}
		return nil
	})
}

type StopIterationError struct {
}

func (e StopIterationError) Error() string {
	return "Stop Iteration"
}

func Iterate(hash []byte, block *Block, cache Cache, callback func([]byte, *Block) error) error {
	// Iterate throught each block in the chain
	if hash == nil {
		return nil
	}
	var err error
	b := block
	if b == nil {
		b, err = cache.GetBlock(hash)
		if err != nil {
			return err
		}
	}
	for b != nil {
		if err = callback(hash, b); err != nil {
			return err
		}
		hash = b.Previous
		if hash != nil && len(hash) > 0 {
			b, err = cache.GetBlock(hash)
			if err != nil {
				return err
			}
		} else {
			b = nil
		}
	}
	return nil
}

func LoadHead(channel Channel, cache Cache, network Network) error {
	reference, err := GetHeadReference(channel.GetName(), cache, network)
	if err != nil {
		return err
	}
	channel.SetTimestamp(reference.Timestamp)
	channel.SetHead(reference.BlockHash)
	return nil
}

func GetHeadReference(channel string, cache Cache, network Network) (*Reference, error) {
	reference, err := cache.GetHead(channel)
	if err != nil {
		if network == nil {
			return nil, err
		} else {
			fmt.Println(err)
		}
	} else {
		return reference, nil
	}
	reference, err = network.GetHead(channel)
	if err != nil {
		return nil, err
	}
	return reference, nil
}

func GetBlock(channel string, cache Cache, network Network, hash []byte) (*Block, error) {
	b, err := cache.GetBlock(hash)
	if err != nil {
		if network == nil {
			return nil, err
		} else {
			fmt.Println(err)
		}
	} else {
		return b, nil
	}

	b, err = network.GetBlock(&Reference{
		ChannelName: channel,
		BlockHash:   hash,
	})
	if err != nil {
		return nil, err
	}

	err = cache.PutBlock(hash, b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func WriteRecord(channel string, cache Cache, record *Record) (*Reference, error) {
	hash, err := HashProtobuf(record)
	if err != nil {
		return nil, err
	}
	if err := cache.PutBlockEntry(channel, &BlockEntry{
		RecordHash: hash,
		Record:     record,
	}); err != nil {
		return nil, err
	}
	return &Reference{
		Timestamp:   record.Timestamp,
		ChannelName: channel,
		RecordHash:  hash,
	}, nil
}

func Pull(channel Channel, cache Cache, network Network) error {
	reference, err := network.GetHead(channel.GetName())
	if err != nil {
		return err
	}
	hash := reference.BlockHash
	if bytes.Equal(channel.GetHead(), hash) {
		// Channel up-to-date
		return nil
	}
	// Load head block
	block, err := GetBlock(channel.GetName(), cache, network, hash)
	if err != nil {
		return err
	}
	// Ensure all previous blocks are loaded
	b := block
	for b != nil {
		h := b.Previous
		if h != nil && len(h) > 0 {
			b, err = GetBlock(channel.GetName(), cache, network, h)
			if err != nil {
				return err
			}
		} else {
			b = nil
		}
	}
	if err := Update(channel, cache, hash, block); err != nil {
		return err
	}
	return nil
}

func Push(channel Channel, cache Cache, network Network) error {
	hash := channel.GetHead()
	block, err := cache.GetBlock(hash)
	if err != nil {
		return err
	}
	return network.Broadcast(channel, cache, hash, block)
}
