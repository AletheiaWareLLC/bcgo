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
	"errors"
	"fmt"
	"strconv"
)

const (
	ERROR_HASH_TOO_WEAK = "Hash doesn't meet Proof-of-Work threshold: %d vs %d"
)

type PoWChannel struct {
	Name      string
	Threshold uint64
	HeadHash  []byte
	Timestamp uint64
}

func OpenPoWChannel(name string, threshold uint64) *PoWChannel {
	return &PoWChannel{
		Name:      name,
		Threshold: threshold,
	}
}

func OpenAndLoadPoWChannel(name string, threshold uint64, cache Cache, network Network) *PoWChannel {
	c := OpenPoWChannel(name, threshold)
	if err := LoadHead(c, cache, network); err != nil {
		fmt.Println(err)
	}
	return c
}

func (p *PoWChannel) GetName() string {
	return p.Name
}

func (p *PoWChannel) GetThreshold() uint64 {
	return p.Threshold
}

func (p *PoWChannel) String() string {
	return p.Name + " " + strconv.FormatUint(p.Threshold, 10)
}

func (p *PoWChannel) Validate(cache Cache, hash []byte, block *Block) error {
	return Iterate(hash, block, cache, func(h []byte, b *Block) error {
		// Check hash ones pass threshold
		ones := Ones(h)
		if ones < p.Threshold {
			return errors.New(fmt.Sprintf(ERROR_HASH_TOO_WEAK, ones, p.Threshold))
		}
		return nil
	})
}

func (p *PoWChannel) GetHead() []byte {
	return p.HeadHash
}

func (p *PoWChannel) SetHead(hash []byte) {
	p.HeadHash = hash
}

func (p *PoWChannel) GetTimestamp() uint64 {
	return p.Timestamp
}

func (p *PoWChannel) SetTimestamp(Timestamp uint64) {
	p.Timestamp = Timestamp
}
