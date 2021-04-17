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
	"testing"
)

func NewMockNetwork(t *testing.T) *MockNetwork {
	t.Helper()
	return &MockNetwork{
		Blocks: make(map[string]*bcgo.Block),
		Heads:  make(map[string]*bcgo.Reference),
	}
}

type MockNetwork struct {
	HeadError      error
	BlockError     error
	RecordError    error
	BroadcastError error
	Blocks         map[string]*bcgo.Block
	Heads          map[string]*bcgo.Reference
	BroadcastHash  []byte
	BroadcastBlock *bcgo.Block
}

func (m *MockNetwork) Head(channel string) (*bcgo.Reference, error) {
	return m.Heads[channel], m.HeadError
}

func (m *MockNetwork) Block(reference *bcgo.Reference) (*bcgo.Block, error) {
	return m.Blocks[base64.RawURLEncoding.EncodeToString(reference.BlockHash)], m.BlockError
}

func (m *MockNetwork) Broadcast(channel bcgo.Channel, cache bcgo.Cache, hash []byte, block *bcgo.Block) error {
	m.BroadcastHash = hash
	m.BroadcastBlock = block
	return m.BroadcastError
}
