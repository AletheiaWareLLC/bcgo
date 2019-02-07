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
	"bufio"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"github.com/golang/protobuf/proto"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	THRESHOLD_NONE     = 0
	THRESHOLD_LITE     = 264 // 33/64
	THRESHOLD_STANDARD = 272 // 17/32
	THRESHOLD_PVB_HOUR = 288 // 9/16
	THRESHOLD_PVB_DAY  = 320 // 5/8
	THRESHOLD_PVB_YEAR = 384 // 3/4

	PORT_BLOCK = 22222
	PORT_HEAD  = 22322
)

var Channels map[string]*Channel

type Channel struct {
	Name      string
	Threshold uint64
	HeadHash  []byte
	HeadBlock *Block
	Cache     string
}

func (c *Channel) Update(hash []byte, block *Block) error {
	if bytes.Equal(c.HeadHash, hash) {
		log.Println(c.Name, "already up to date")
		return nil
	}
	c.HeadHash = hash
	// TODO check hash matches block hash
	// TODO check hash ones pass threshold
	head := Reference{
		Timestamp:   block.Timestamp,
		ChannelName: c.Name,
		BlockHash:   hash,
	}
	if err := WriteHeadFile(c.Cache, c.Name, &head); err != nil {
		return err
	}
	c.HeadBlock = block
	log.Println(c.Name, "updated to", base64.RawURLEncoding.EncodeToString(hash))
	return WriteBlockFile(c.Cache, hash, block)
}

func (c *Channel) LoadHead() error {
	head, err := ReadHeadFile(c.Cache, c.Name)
	if err != nil {
		return err
	}
	c.HeadHash = head.BlockHash
	block, err := ReadBlockFile(c.Cache, head.BlockHash)
	if err != nil {
		return err
	}
	c.HeadBlock = block
	return nil
}

func (c *Channel) Read(alias string, key *rsa.PrivateKey, recordHash []byte, callback func(*BlockEntry, []byte)) error {
	// Decrypt each record in chain and pass to the given callback
	log.Println("Reading", c.Name, "for", alias)
	b := c.HeadBlock
	for b != nil {
		for _, e := range b.Entry {
			if recordHash == nil || bytes.Equal(recordHash, e.RecordHash) {
				for _, a := range e.Record.Access {
					if a.Alias == alias {
						if err := DecryptRecord(e, a, key, callback); err != nil {
							log.Println(err)
						}
					}
				}
			}
		}
		h := b.Previous
		if h != nil && len(h) > 0 {
			var err error
			b, err = ReadBlockFile(c.Cache, h)
			if err != nil {
				return err
			}
		} else {
			b = nil
		}
	}
	return nil
}

func (c *Channel) Sync() error {
	log.Println("Syncing", c.Name)
	head, err := GetHead(c.Name)
	if err != nil {
		return err
	}
	hash := head.BlockHash
	if !bytes.Equal(c.HeadHash, hash) {
		// Load head block
		block, err := ReadBlockFile(c.Cache, hash)
		if err != nil {
			log.Println(err)
			block, err = GetBlock(head)
			if err != nil {
				return err
			}
		}
		// Ensure all previous blocks are loaded
		b := block
		for b != nil {
			h := b.Previous
			if h != nil && len(h) > 0 {
				var err error
				b, err = ReadBlockFile(c.Cache, h)
				if err != nil {
					log.Println(err)
					b, err = GetBlock(&Reference{
						ChannelName: c.Name,
						BlockHash:   h,
					})
					if err != nil {
						return err
					}
					err = WriteBlockFile(c.Cache, h, b)
					if err != nil {
						return err
					}
				}
			} else {
				b = nil
			}
		}
		if err := c.Update(hash, block); err != nil {
			return err
		}
	}
	return nil
}

func GetHead(channel string) (*Reference, error) {
	hosts, err := GetHosts()
	if err != nil {
		return nil, err
	}
	for _, host := range hosts {
		if len(host) > 0 {
			address := host + ":" + strconv.Itoa(PORT_HEAD)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				log.Println(err)
				continue
			}
			defer connection.Close()
			reader := bufio.NewReader(connection)
			writer := bufio.NewWriter(connection)
			if err := WriteReference(writer, &Reference{
				ChannelName: channel,
			}); err != nil {
				log.Println(err)
				continue
			}
			reference, err := ReadReference(reader)
			if err != nil {
				log.Println(err)
				continue
			} else {
				return reference, nil
			}
		}
	}
	return nil, errors.New("Couldn't get head from hosts")
}

func GetBlock(reference *Reference) (*Block, error) {
	hosts, err := GetHosts()
	if err != nil {
		return nil, err
	}
	for _, host := range hosts {
		if len(host) > 0 {
			address := host + ":" + strconv.Itoa(PORT_BLOCK)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				log.Println(err)
				continue
			}
			defer connection.Close()
			reader := bufio.NewReader(connection)
			writer := bufio.NewWriter(connection)
			if err := WriteReference(writer, reference); err != nil {
				log.Println(err)
				continue
			}
			block, err := ReadBlock(reader)
			if err != nil {
				log.Println(err)
				continue
			} else {
				return block, nil
			}
		}
	}
	return nil, errors.New("Couldn't get block from hosts")
}

func OpenChannel(name string) (*Channel, error) {
	if Channels == nil {
		Channels = make(map[string]*Channel)
	}
	channel, ok := Channels[name]
	if !ok {
		cache, err := GetCache()
		if err != nil {
			return nil, err
		}
		channel = &Channel{
			Name:      name,
			Threshold: THRESHOLD_STANDARD,
			Cache:     cache,
		}
		Channels[name] = channel
		if err := channel.LoadHead(); err != nil {
			log.Println(err)
		}
	}
	if err := channel.Sync(); err != nil {
		log.Println(err)
	}
	return channel, nil
}

type Node struct {
	Alias string
	Key   *rsa.PrivateKey
}

func GetNode() (*Node, error) {
	// Load private key
	a, k, err := GetOrCreateRSAPrivateKey()
	if err != nil {
		return nil, err
	}
	return &Node{
		Alias: a,
		Key:   k,
	}, nil
}

func (n *Node) Mine(channel *Channel, acl map[string]*rsa.PublicKey, data []byte) (*Reference, error) {
	record, err := CreateRecord(n.Alias, n.Key, acl, nil, data)
	if err != nil {
		return nil, err
	}

	data, err = proto.Marshal(record)
	if err != nil {
		return nil, err
	}

	entries := [1]*BlockEntry{
		&BlockEntry{
			RecordHash: Hash(data),
			Record:     record,
		},
	}

	hash, block, err := n.MineRecords(channel, entries[:])
	if err != nil {
		return nil, err
	}
	n.Multicast(channel, hash, block)
	return &Reference{
		Timestamp:   block.Timestamp,
		ChannelName: channel.Name,
		BlockHash:   hash,
	}, nil
}

func (n *Node) MineRecords(channel *Channel, entries []*BlockEntry) ([]byte, *Block, error) {
	block := &Block{
		Timestamp:   uint64(time.Now().UnixNano()),
		ChannelName: channel.Name,
		Length:      1,
		Miner:       n.Alias,
		Entry:       entries,
	}

	previous := channel.HeadBlock
	if previous != nil {
		block.Length = previous.Length + 1
		data, err := proto.Marshal(previous)
		if err != nil {
			return nil, nil, err
		}
		block.Previous = Hash(data)
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
		hash := Hash(data)
		ones := Ones(hash)
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

func (n *Node) Multicast(channel *Channel, hash []byte, block *Block) error {
	log.Println("Channel", channel)
	log.Println("Hash", hash)
	log.Println("Block", block)
	// TODO
	return nil
}
