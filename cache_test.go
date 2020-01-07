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

package bcgo_test

import (
	"encoding/base64"
	"errors"
	"github.com/AletheiaWareLLC/bcgo"
	"testing"
)

func makeMockCache(t *testing.T) *MockCache {
	t.Helper()
	return &MockCache{
		Block:   make(map[string]*bcgo.Block),
		Head:    make(map[string]*bcgo.Reference),
		Entries: make(map[string][]*bcgo.BlockEntry),
	}
}

type MockCache struct {
	Channel            []string
	Hash               [][]byte
	Block              map[string]*bcgo.Block
	Head               map[string]*bcgo.Reference
	Entries            map[string][]*bcgo.BlockEntry
	EntryTimes         []uint64
	PutHeadError       error
	PutBlockError      error
	PutBlockEntryError error
	DeleteBlockError   error
	RecordToBlock      map[string]*bcgo.Block
}

func (m *MockCache) GetBlock(hash []byte) (*bcgo.Block, error) {
	m.Hash = append(m.Hash, hash)
	if len(m.Block) == 0 {
		return nil, errors.New("No Blocks")
	}
	key := base64.RawURLEncoding.EncodeToString(hash)
	result, ok := m.Block[key]
	if !ok {
		return nil, errors.New("Cannot get block: " + key)
	}
	return result, nil
}

func (m *MockCache) GetHead(channel string) (*bcgo.Reference, error) {
	m.Channel = append(m.Channel, channel)
	if len(m.Head) == 0 {
		return nil, errors.New("No Head")
	}
	result, ok := m.Head[channel]
	if !ok {
		return nil, errors.New("Cannot get head: " + channel)
	}
	return result, nil
}

func (m *MockCache) GetBlockEntries(channel string, timestamp uint64) ([]*bcgo.BlockEntry, error) {
	m.Channel = append(m.Channel, channel)
	m.EntryTimes = append(m.EntryTimes, timestamp)
	return m.Entries[channel][:], nil
}

func (m *MockCache) GetBlockContainingRecord(channel string, hash []byte) (*bcgo.Block, error) {
	return m.RecordToBlock[base64.RawURLEncoding.EncodeToString(hash)], nil
}

func (m *MockCache) PutBlock(hash []byte, block *bcgo.Block) error {
	m.Hash = append(m.Hash, hash)
	m.Block[base64.RawURLEncoding.EncodeToString(hash)] = block
	return m.PutBlockError
}

func (m *MockCache) PutHead(channel string, reference *bcgo.Reference) error {
	m.Channel = append(m.Channel, channel)
	m.Head[channel] = reference
	return m.PutHeadError
}

func (m *MockCache) PutBlockEntry(channel string, entry *bcgo.BlockEntry) error {
	m.Channel = append(m.Channel, channel)
	m.Entries[channel] = append(m.Entries[channel], entry)
	return m.PutBlockEntryError
}

// func (m *MockCache) DeleteBlock(hash []byte) error {
// 	delete(m.Block, base64.RawURLEncoding.EncodeToString(hash))
// 	return m.DeleteBlockError
// }
