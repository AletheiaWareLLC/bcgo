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
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/AletheiaWareLLC/cryptogo"
	"github.com/golang/protobuf/proto"
	"sort"
)

const (
	ERROR_NO_ENTRIES_TO_MINE = "No entries to mine for channel: %s"
	ERROR_NO_SUCH_CHANNEL    = "No such channel: %s"
	ERROR_PAYLOAD_TOO_LARGE  = "Payload too large: %s max: %s"
	ERROR_BLOCK_TOO_LARGE    = "Block too large: %s max: %s"
	ERROR_NONCE_WRAP_AROUND  = "Nonce wrapped around before reaching threshold"
)

type MiningListener interface {
	OnMiningStarted(channel ThresholdChannel, size uint64)
	OnNewMaxOnes(channel ThresholdChannel, nonce, ones uint64)
	OnMiningThresholdReached(channel ThresholdChannel, hash []byte, block *Block)
}

type Node struct {
	Alias    string
	Key      *rsa.PrivateKey
	Cache    Cache
	Network  Network
	Channels map[string]ThresholdChannel
}

func GetNode(directory string, cache Cache, network Network) (*Node, error) {
	// Get alias
	alias, err := GetAlias()
	if err != nil {
		return nil, err
	}
	keystore, err := GetKeyDirectory(directory)
	if err != nil {
		return nil, err
	}
	// Get private key
	key, err := cryptogo.GetOrCreateRSAPrivateKey(keystore, alias)
	if err != nil {
		return nil, err
	}
	return &Node{
		Alias:    alias,
		Key:      key,
		Cache:    cache,
		Network:  network,
		Channels: make(map[string]ThresholdChannel),
	}, nil
}

func (n *Node) AddChannel(channel ThresholdChannel) {
	n.Channels[channel.GetName()] = channel
}

func (n *Node) GetChannel(name string) (ThresholdChannel, error) {
	c, ok := n.Channels[name]
	if !ok {
		return nil, errors.New(fmt.Sprintf(ERROR_NO_SUCH_CHANNEL, name))
	}
	return c, nil
}

func (n *Node) GetChannels() []Channel {
	var keys []string
	for k := range n.Channels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var channels []Channel
	for _, k := range keys {
		channels = append(channels, n.Channels[k])
	}
	return channels
}

func (n *Node) Write(timestamp uint64, channel ThresholdChannel, acl map[string]*rsa.PublicKey, references []*Reference, payload []byte) (*Reference, error) {
	size := uint64(len(payload))
	if size > MAX_PAYLOAD_SIZE_BYTES {
		return nil, errors.New(fmt.Sprintf(ERROR_PAYLOAD_TOO_LARGE, BinarySizeToString(size), BinarySizeToString(MAX_PAYLOAD_SIZE_BYTES)))
	}
	_, record, err := CreateRecord(timestamp, n.Alias, n.Key, acl, references, payload)
	if err != nil {
		return nil, err
	}
	return WriteRecord(channel.GetName(), n.Cache, record)
}

func (n *Node) GetLastMinedTimestamp(channel ThresholdChannel) (uint64, error) {
	var timestamp uint64
	// Iterate through the chain to find the most recent block mined by this node
	if err := Iterate(channel.GetName(), channel.GetHead(), nil, n.Cache, n.Network, func(h []byte, b *Block) error {
		if b.Miner == n.Alias {
			timestamp = b.Timestamp
			return StopIterationError{}
		}
		return nil
	}); err != nil {
		switch err.(type) {
		case StopIterationError:
			// Do nothing
			break
		default:
			return 0, err
		}
	}
	return timestamp, nil
}

func (n *Node) Mine(channel ThresholdChannel, listener MiningListener) ([]byte, *Block, error) {
	timestamp, err := n.GetLastMinedTimestamp(channel)
	if err != nil {
		return nil, nil, err
	}

	entries, err := n.Cache.GetBlockEntries(channel.GetName(), timestamp)
	if err != nil {
		return nil, nil, err
	}

	if len(entries) == 0 {
		return nil, nil, errors.New(fmt.Sprintf(ERROR_NO_ENTRIES_TO_MINE, channel.GetName()))
	}

	// TODO check record signature of each entry

	block := &Block{
		Timestamp:   Timestamp(),
		ChannelName: channel.GetName(),
		Length:      1,
		Miner:       n.Alias,
		Entry:       entries,
	}

	previousHash := channel.GetHead()
	if previousHash != nil {
		previousBlock, err := n.Cache.GetBlock(previousHash)
		if err != nil {
			return nil, nil, err
		}
		block.Length = previousBlock.Length + 1
		block.Previous = previousHash
	}

	size := uint64(proto.Size(block))
	if size > MAX_BLOCK_SIZE_BYTES {
		return nil, nil, errors.New(fmt.Sprintf(ERROR_BLOCK_TOO_LARGE, BinarySizeToString(size), BinarySizeToString(MAX_BLOCK_SIZE_BYTES)))
	}

	if listener != nil {
		listener.OnMiningStarted(channel, size)
	}

	var max uint64
	for nonce := uint64(1); nonce > 0; nonce++ {
		block.Nonce = nonce
		hash, err := cryptogo.HashProtobuf(block)
		if err != nil {
			return nil, nil, err
		}
		ones := Ones(hash)
		if ones > max {
			if listener != nil {
				listener.OnNewMaxOnes(channel, nonce, ones)
			}
			max = ones
		}
		if ones > channel.GetThreshold() {
			if listener != nil {
				listener.OnMiningThresholdReached(channel, hash, block)
			}
			if err := Update(channel, n.Cache, n.Network, hash, block); err != nil {
				return nil, nil, err
			}
			return hash, block, nil
		}
	}
	return nil, nil, errors.New(ERROR_NONCE_WRAP_AROUND)
}
