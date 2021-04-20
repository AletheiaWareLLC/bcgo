/*
 * Copyright 2019-21 Aletheia Ware LLC
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

package test

import (
	"aletheiaware.com/bcgo"
	"encoding/base64"
	"errors"
	"testing"
)

func NewMockCache(t *testing.T) *MockCache {
	t.Helper()
	return &MockCache{
		Blocks:  make(map[string]*bcgo.Block),
		Heads:   make(map[string]*bcgo.Reference),
		Entries: make(map[string][]*bcgo.BlockEntry),
	}
}

type MockCache struct {
	Channel            []string
	Hash               [][]byte
	Blocks             map[string]*bcgo.Block
	Heads              map[string]*bcgo.Reference
	Entries            map[string][]*bcgo.BlockEntry
	EntryTimes         []uint64
	PutHeadError       error
	PutBlockError      error
	PutBlockEntryError error
	DeleteBlockError   error
	RecordToBlock      map[string]*bcgo.Block
}

func (m *MockCache) Block(hash []byte) (*bcgo.Block, error) {
	m.Hash = append(m.Hash, hash)
	if len(m.Blocks) == 0 {
		return nil, errors.New("No Such Block")
	}
	key := base64.RawURLEncoding.EncodeToString(hash)
	result, ok := m.Blocks[key]
	if !ok {
		return nil, errors.New("Cannot get block: " + key)
	}
	return result, nil
}

func (m *MockCache) Head(channel string) (*bcgo.Reference, error) {
	m.Channel = append(m.Channel, channel)
	if len(m.Heads) == 0 {
		return nil, errors.New("No Such Head")
	}
	result, ok := m.Heads[channel]
	if !ok {
		return nil, errors.New("Cannot get head: " + channel)
	}
	return result, nil
}

func (m *MockCache) BlockEntries(channel string, timestamp uint64) ([]*bcgo.BlockEntry, error) {
	m.Channel = append(m.Channel, channel)
	m.EntryTimes = append(m.EntryTimes, timestamp)
	return m.Entries[channel][:], nil
}

func (m *MockCache) BlockContainingRecord(channel string, hash []byte) (*bcgo.Block, error) {
	return m.RecordToBlock[base64.RawURLEncoding.EncodeToString(hash)], nil
}

func (m *MockCache) PutBlock(hash []byte, block *bcgo.Block) error {
	m.Hash = append(m.Hash, hash)
	m.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
	return m.PutBlockError
}

func (m *MockCache) PutHead(channel string, reference *bcgo.Reference) error {
	m.Channel = append(m.Channel, channel)
	m.Heads[channel] = reference
	return m.PutHeadError
}

func (m *MockCache) PutBlockEntry(channel string, entry *bcgo.BlockEntry) error {
	m.Channel = append(m.Channel, channel)
	m.Entries[channel] = append(m.Entries[channel], entry)
	return m.PutBlockEntryError
}

// func (m *MockCache) DeleteBlock(hash []byte) error {
// 	delete(m.Blocks, base64.RawURLEncoding.EncodeToString(hash))
// 	return m.DeleteBlockError
// }
