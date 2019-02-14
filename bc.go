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

	PORT_BLOCK     = 22222
	PORT_HEAD      = 22322
	PORT_MULTICAST = 23232

	MAX_BLOCK_SIZE_BYTES   = uint64(2 * 1024 * 1024 * 1024) // 2Gb
	MAX_PAYLOAD_SIZE_BYTES = uint64(500 * 1024 * 1024)      // 500Mb
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
		// Channel up to date
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
	block, err := c.GetBlock(head.BlockHash)
	if err != nil {
		return err
	}
	c.HeadBlock = block
	return nil
}

func (c *Channel) GetHead() ([]byte, error) {
	if c.HeadHash == nil {
		if err := c.LoadHead(); err != nil {
			log.Println(err)
		}
	}
	if c.HeadHash == nil {
		reference, err := c.GetRemoteHead()
		if err != nil {
			return nil, err
		}
		c.HeadHash = reference.BlockHash
	}
	return c.HeadHash, nil
}

func (c *Channel) GetBlock(hash []byte) (*Block, error) {
	b, err := ReadBlockFile(c.Cache, hash)
	if err != nil {
		log.Println(err)
		b, err = c.GetRemoteBlock(&Reference{
			ChannelName: c.Name,
			BlockHash:   hash,
		})
		if err != nil {
			return nil, err
		}
		err = WriteBlockFile(c.Cache, hash, b)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (c *Channel) GetKey(alias string, key *rsa.PrivateKey, recordHash []byte, callback func([]byte) error) error {
	block, err := c.GetRemoteBlock(&Reference{
		ChannelName: c.Name,
		RecordHash:  recordHash,
	})
	if err != nil {
		return err
	}
	for _, entry := range block.Entry {
		if bytes.Equal(recordHash, entry.RecordHash) {
			for _, access := range entry.Record.Access {
				if alias == access.Alias {
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
}

func (c *Channel) Read(alias string, key *rsa.PrivateKey, recordHash []byte, callback func(*BlockEntry, []byte, []byte) error) error {
	return c.Iterate(func(h []byte, b *Block) error {
		for _, entry := range b.Entry {
			if recordHash == nil || bytes.Equal(recordHash, entry.RecordHash) {
				for _, access := range entry.Record.Access {
					if alias == access.Alias {
						if err := DecryptRecord(entry, access, key, callback); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
}

func (c *Channel) Iterate(callback func([]byte, *Block) error) error {
	// Decrypt each record in chain and pass to the given callback
	h := c.HeadHash
	b := c.HeadBlock
	for b != nil {
		if err := callback(h, b); err != nil {
			return err
		}
		h = b.Previous
		if h != nil && len(h) > 0 {
			var err error
			b, err = c.GetBlock(h)
			if err != nil {
				return nil
			}
		} else {
			b = nil
		}
	}
	return nil
}

func (c *Channel) Sync() error {
	reference, err := c.GetRemoteHead()
	if err != nil {
		return err
	}
	head := reference.BlockHash
	if bytes.Equal(c.HeadHash, head) {
		// Channel up-to-date
		return nil
	}
	// Load head block
	block, err := c.GetBlock(head)
	if err != nil {
		return err
	}
	// Ensure all previous blocks are loaded
	b := block
	for b != nil {
		hash := b.Previous
		if hash != nil && len(hash) > 0 {
			var err error
			b, err = c.GetBlock(hash)
			if err != nil {
				return err
			}
		} else {
			b = nil
		}
	}
	if err := c.Update(head, block); err != nil {
		return err
	}
	return nil
}

func (c *Channel) GetRemoteHead() (*Reference, error) {
	peers, err := GetPeers()
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if len(peer) > 0 {
			address := peer + ":" + strconv.Itoa(PORT_HEAD)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				log.Println(err)
				continue
			}
			defer connection.Close()
			reader := bufio.NewReader(connection)
			writer := bufio.NewWriter(connection)
			if err := WriteReference(writer, &Reference{
				ChannelName: c.Name,
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
	return nil, errors.New("Couldn't get " + c.Name + " head from peers")
}

func (c *Channel) GetRemoteBlock(reference *Reference) (*Block, error) {
	peers, err := GetPeers()
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if len(peer) > 0 {
			address := peer + ":" + strconv.Itoa(PORT_BLOCK)
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
	return nil, errors.New("Couldn't get " + reference.ChannelName + " block from peers")
}

func (c *Channel) Multicast(hash []byte, block *Block) error {
	log.Println("Multicasting", c.Name, base64.RawURLEncoding.EncodeToString(hash))
	peers, err := GetPeers()
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if len(peer) > 0 {
			address := peer + ":" + strconv.Itoa(PORT_MULTICAST)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				return err
			}
			defer connection.Close()
			writer := bufio.NewWriter(connection)
			if err := WriteBlock(writer, block); err != nil {
				return err
			}
			reader := bufio.NewReader(connection)
			reference, err := ReadReference(reader)
			if err != nil {
				return err
			}
			// Multicast received, reference holds remote channel current head
			if bytes.Equal(hash, reference.BlockHash) {
				// Multicast accepted
			} else {
				// Multicast rejected
				block, err := c.GetBlock(reference.BlockHash)
				if err != nil {
					return err
				}
				if err := c.Update(reference.BlockHash, block); err != nil {
					return err
				}
				return errors.New("Block Not Mined On Channel Head")
			}
		}
	}
	return nil
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
	return channel, nil
}

func OpenAndSyncChannel(name string) (*Channel, error) {
	channel, err := OpenChannel(name)
	if err != nil {
		return nil, err
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

// TODO Split into:
// Write - Create Record, Write to FileSystem
// Mine - Load Records from FileSystem, Check Record Signature, Check Record Creator is this node, Filter out records that already appear in the chain, Mine into Channel's Blockchain
func (n *Node) Mine(channel *Channel, acl map[string]*rsa.PublicKey, references []*Reference, payload []byte) (*Reference, error) {
	size := uint64(len(payload))
	if size > MAX_PAYLOAD_SIZE_BYTES {
		return nil, errors.New("Payload too large: " + SizeToString(size) + " max: " + SizeToString(MAX_PAYLOAD_SIZE_BYTES))
	}
	_, record, err := CreateRecord(n.Alias, n.Key, acl, references, payload)
	if err != nil {
		return nil, err
	}
	return n.MineRecord(channel, record)
}

func (n *Node) MineRecord(channel *Channel, record *Record) (*Reference, error) {
	data, err := proto.Marshal(record)
	if err != nil {
		return nil, err
	}
	recordHash := Hash(data)
	entries := []*BlockEntry{&BlockEntry{
		RecordHash: recordHash,
		Record:     record,
	}}

	blockHash, block, err := n.MineRecords(channel, entries[:])
	if err != nil {
		return nil, err
	}
	return &Reference{
		Timestamp:   block.Timestamp,
		ChannelName: channel.Name,
		BlockHash:   blockHash,
		RecordHash:  recordHash,
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

	previousHash := channel.HeadHash
	previousBlock := channel.HeadBlock
	if previousHash != nil && previousBlock != nil {
		block.Length = previousBlock.Length + 1
		block.Previous = previousHash
	}

	size := uint64(proto.Size(block))
	if size > MAX_BLOCK_SIZE_BYTES {
		return nil, nil, errors.New("Block too large: " + SizeToString(size) + " max: " + SizeToString(MAX_BLOCK_SIZE_BYTES))
	}
	log.Println("Mining", channel.Name, size)

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
			log.Println("Mined", channel.Name, TimestampToString(block.Timestamp), base64.RawURLEncoding.EncodeToString(hash))
			if err := channel.Update(hash, block); err != nil {
				return nil, nil, err
			}
			if err := channel.Multicast(hash, block); err != nil {
				log.Println("Multicast Error:", err)
				// TODO re-mine all records created by this node not already mined into the Channel's Blockchain
			}
			return hash, block, nil
		}
	}
	return nil, nil, errors.New("Nonce wrapped around before reaching threshold")
}
