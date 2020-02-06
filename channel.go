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
	"github.com/AletheiaWareLLC/cryptogo"
)

const (
	ERROR_CHAIN_INVALID   = "Chain invalid: %s"
	ERROR_CHAIN_TOO_SHORT = "Chain too short to replace current head: %d vs %d"
	ERROR_HASH_INCORRECT  = "Hash doesn't match block hash"
)

type Channel struct {
	Name       string
	Head       []byte
	Timestamp  uint64
	Triggers   []func()
	Validators []Validator
}

func (c *Channel) String() string {
	return c.Name
}

func (c *Channel) AddTrigger(trigger func()) {
	c.Triggers = append(c.Triggers, trigger)
}

func (c *Channel) AddValidator(validator Validator) {
	c.Validators = append(c.Validators, validator)
}

func (c *Channel) Update(cache Cache, network Network, head []byte, block *Block) error {
	if bytes.Equal(c.Head, head) {
		// Channel up to date
		return nil
	}

	// Check hash matches block hash
	h, err := cryptogo.HashProtobuf(block)
	if err != nil {
		return err
	}
	if !bytes.Equal(head, h) {
		return errors.New(ERROR_HASH_INCORRECT)
	}
	if c.Head != nil {
		b, err := cache.GetBlock(c.Head)
		if err != nil {
			return err
		}
		// Check block chain is longer than current head
		if b != nil && b.Length >= block.Length {
			return errors.New(fmt.Sprintf(ERROR_CHAIN_TOO_SHORT, block.Length, b.Length))
		}
	}

	for _, v := range c.Validators {
		if err := v.Validate(c, cache, network, head, block); err != nil {
			return errors.New(fmt.Sprintf(ERROR_CHAIN_INVALID, err.Error()))
		}
	}

	if err := cache.PutHead(c.Name, &Reference{
		Timestamp:   block.Timestamp,
		ChannelName: c.Name,
		BlockHash:   head,
	}); err != nil {
		return err
	}
	if err := cache.PutBlock(head, block); err != nil {
		return err
	}
	c.update(block.Timestamp, head)
	return nil
}

func (c *Channel) update(timestamp uint64, head []byte) {
	c.Timestamp = timestamp
	c.Head = head
	fmt.Printf("%s updated to %s %s\n", c.Name, TimestampToString(timestamp), base64.RawURLEncoding.EncodeToString(head))
	for _, t := range c.Triggers {
		t()
	}
}

func ReadKey(channel string, hash []byte, block *Block, cache Cache, network Network, alias string, key *rsa.PrivateKey, recordHash []byte, callback func([]byte) error) error {
	return Iterate(channel, hash, block, cache, network, func(h []byte, b *Block) error {
		for _, entry := range b.Entry {
			if recordHash == nil || bytes.Equal(recordHash, entry.RecordHash) {
				if len(entry.Record.Access) == 0 {
					// No Access Declared - Data is public and unencrypted
					if err := callback(nil); err != nil {
						return err
					}
				} else {
					for _, access := range entry.Record.Access {
						if alias == "" || alias == access.Alias {
							decryptedKey, err := cryptogo.DecryptKey(access.EncryptionAlgorithm, access.SecretKey, key)
							if err != nil {
								return err
							}
							if err := callback(decryptedKey); err != nil {
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

func Read(channel string, hash []byte, block *Block, cache Cache, network Network, alias string, key *rsa.PrivateKey, recordHash []byte, callback func(*BlockEntry, []byte, []byte) error) error {
	// Decrypt each record in chain and pass to the given callback
	return Iterate(channel, hash, block, cache, network, func(h []byte, b *Block) error {
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

func Iterate(channel string, hash []byte, block *Block, cache Cache, network Network, callback func([]byte, *Block) error) error {
	// Iterate throught each block in the chain
	if hash == nil {
		return nil
	}
	var err error
	b := block
	if b == nil {
		b, err = GetBlock(channel, cache, network, hash)
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
			b, err = GetBlock(channel, cache, network, hash)
			if err != nil {
				return err
			}
		} else {
			b = nil
		}
	}
	return nil
}

func (c *Channel) LoadCachedHead(cache Cache) error {
	reference, err := cache.GetHead(c.Name)
	if err != nil {
		return err
	}
	c.update(reference.Timestamp, reference.BlockHash)
	return nil
}

func (c *Channel) LoadHead(cache Cache, network Network) error {
	reference, err := GetHeadReference(c.Name, cache, network)
	if err != nil {
		return err
	}
	c.update(reference.Timestamp, reference.BlockHash)
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

	if err := cache.PutBlock(hash, b); err != nil {
		return nil, err
	}

	return b, nil
}

func GetBlockContainingRecord(channel string, cache Cache, network Network, hash []byte) (*Block, error) {
	b, err := cache.GetBlockContainingRecord(channel, hash)
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
		RecordHash:  hash,
	})
	if err != nil {
		return nil, err
	}

	bh, err := cryptogo.HashProtobuf(b)
	if err != nil {
		return nil, err
	}

	if err := cache.PutBlock(bh, b); err != nil {
		return nil, err
	}

	return b, nil
}

func WriteRecord(channel string, cache Cache, record *Record) (*Reference, error) {
	hash, err := cryptogo.HashProtobuf(record)
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

func (c *Channel) Pull(cache Cache, network Network) error {
	if network == nil {
		return nil
	}
	reference, err := network.GetHead(c.Name)
	if err != nil {
		return err
	}
	hash := reference.BlockHash
	if bytes.Equal(c.Head, hash) {
		// Channel up-to-date
		return nil
	}
	// Load head block
	block, err := GetBlock(c.Name, cache, network, hash)
	if err != nil {
		return err
	}
	// Ensure all previous blocks are loaded
	b := block
	for b != nil {
		h := b.Previous
		if h != nil && len(h) > 0 {
			b, err = GetBlock(c.Name, cache, network, h)
			if err != nil {
				return err
			}
		} else {
			b = nil
		}
	}
	if err := c.Update(cache, network, hash, block); err != nil {
		return err
	}
	return nil
}

func (c *Channel) Push(cache Cache, network Network) error {
	hash := c.Head
	if hash == nil {
		reference, err := cache.GetHead(c.Name)
		if err != nil {
			return err
		}
		hash = reference.BlockHash
	}
	block, err := cache.GetBlock(hash)
	if err != nil {
		return err
	}
	return network.Broadcast(c, cache, hash, block)
}
