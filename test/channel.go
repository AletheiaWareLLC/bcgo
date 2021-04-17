/*
 * Copyright 2021 Aletheia Ware LLC
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
	"testing"
)

func AssertNilHead(t *testing.T, channel bcgo.Channel) {
	t.Helper()
	if channel.Head() != nil {
		t.Fatal("Expected nil head hash")
	}
}

func NewMockChannel(t *testing.T) *MockChannel {
	t.Helper()
	return &MockChannel{name: "TEST"}
}

type MockChannel struct {
	name                                                       string
	head                                                       []byte
	timestamp                                                  uint64
	UpdateError, LoadError, RefreshError, PullError, PushError error
}

func (c *MockChannel) String() string {
	return c.name
}

func (c *MockChannel) Name() string {
	return c.name
}

func (c *MockChannel) Head() []byte {
	return c.head
}

func (c *MockChannel) Timestamp() uint64 {
	return c.timestamp
}

func (c *MockChannel) AddTrigger(func()) {
	// TODO
}

func (c *MockChannel) AddValidator(bcgo.Validator) {
	// TODO
}

func (c *MockChannel) Update(bcgo.Cache, bcgo.Network, []byte, *bcgo.Block) error {
	return c.UpdateError
}

func (c *MockChannel) Load(bcgo.Cache, bcgo.Network) error {
	return c.LoadError
}

func (c *MockChannel) Refresh(bcgo.Cache, bcgo.Network) error {
	return c.RefreshError
}

func (c *MockChannel) Pull(bcgo.Cache, bcgo.Network) error {
	return c.PullError
}

func (c *MockChannel) Push(bcgo.Cache, bcgo.Network) error {
	return c.PushError
}

func (c *MockChannel) Set(t uint64, h []byte) {
	c.timestamp = t
	c.head = h
}
