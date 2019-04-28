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
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	ERROR_BLOCK_NOT_FOUND = "Block not found %s"
	ERROR_HEAD_NOT_FOUND  = "Head not found %s"
)

type MemoryCache struct {
	Block   map[string]*Block
	Head    map[string]*Reference
	Entries map[string][]*BlockEntry
}

func NewMemoryCache(size int) *MemoryCache {
	// TODO size for blocks, heads, entries
	// TODO implement LRU
	// TODO implement cache levels where
	return &MemoryCache{
		Block:   make(map[string]*Block, size),
		Head:    make(map[string]*Reference, size),
		Entries: make(map[string][]*BlockEntry, size),
	}
}

func (m *MemoryCache) GetBlock(hash []byte) (*Block, error) {
	key := base64.RawURLEncoding.EncodeToString(hash)
	block, ok := m.Block[key]
	if !ok {
		return nil, errors.New(fmt.Sprintf(ERROR_BLOCK_NOT_FOUND, key))
	}
	return block, nil
}

func (m *MemoryCache) GetBlockEntries(channel string, timestamp uint64) ([]*BlockEntry, error) {
	var results []*BlockEntry
	for _, e := range m.Entries[channel] {
		if e.Record.Timestamp >= timestamp {
			results = append(results, e)
		}
	}
	return results, nil
}

func (m *MemoryCache) GetHead(channel string) (*Reference, error) {
	reference, ok := m.Head[channel]
	if !ok {
		return nil, errors.New(fmt.Sprintf(ERROR_HEAD_NOT_FOUND, channel))
	}
	return reference, nil
}

func (m *MemoryCache) PutBlock(hash []byte, block *Block) error {
	m.Block[base64.RawURLEncoding.EncodeToString(hash)] = block
	return nil
}

func (m *MemoryCache) PutBlockEntry(channel string, entry *BlockEntry) error {
	m.Entries[channel] = append(m.Entries[channel], entry)
	return nil
}

func (m *MemoryCache) PutHead(channel string, reference *Reference) error {
	m.Head[channel] = reference
	return nil
}

// func (m *MemoryCache) DeleteBlock(hash []byte) error {
// 	delete(m.Block, base64.RawURLEncoding.EncodeToString(hash))
// 	return nil
// }
