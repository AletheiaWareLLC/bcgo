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
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"time"
)

const (
	PORT_CONNECT   = 22022
	PORT_GET_BLOCK = 22222
	PORT_GET_HEAD  = 22322
	PORT_BROADCAST = 23232
)

type TCPNetwork struct {
	Peers       map[string]int
	DialTimeout time.Duration
}

func NewTCPNetwork(peers ...string) *TCPNetwork {
	t := &TCPNetwork{
		Peers:       make(map[string]int),
		DialTimeout: time.Minute,
	}
	for _, p := range peers {
		t.AddPeer(p)
	}
	return t
}

// Returns a slice of peers sorted by ascending error rate
func (t *TCPNetwork) peers() []string {
	var peers []string
	for p := range t.Peers {
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool {
		return t.Peers[peers[i]] > t.Peers[peers[j]]
	})
	return peers
}

func (t *TCPNetwork) error(peer string, err error) {
	fmt.Println(err)
	t.Peers[peer] = t.Peers[peer] + 1
}

func (t *TCPNetwork) AddPeer(peer string) {
	t.Peers[peer] = 0
}

func (t *TCPNetwork) Connect(peer string, data []byte) error {
	address := net.JoinHostPort(peer, strconv.Itoa(PORT_CONNECT))
	dialer := &net.Dialer{Timeout: t.DialTimeout}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	writer := bufio.NewWriter(connection)
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	reply := make([]byte, len(data))
	reader := bufio.NewReader(connection)
	if _, err := reader.Read(reply); err != nil {
		return err
	}
	fmt.Println(reply)
	t.AddPeer(peer)
	return nil
}

func (t *TCPNetwork) GetHead(channel string) (*Reference, error) {
	for _, peer := range t.peers() {
		if len(peer) > 0 {
			address := net.JoinHostPort(peer, strconv.Itoa(PORT_GET_HEAD))
			dialer := &net.Dialer{Timeout: t.DialTimeout}
			connection, err := dialer.Dial("tcp", address)
			if err != nil {
				t.error(peer, err)
				continue
			}
			defer connection.Close()
			writer := bufio.NewWriter(connection)
			if err := WriteDelimitedProtobuf(writer, &Reference{
				ChannelName: channel,
			}); err != nil {
				t.error(peer, err)
				continue
			}
			reader := bufio.NewReader(connection)
			reference := &Reference{}
			if err := ReadDelimitedProtobuf(reader, reference); err != nil {
				if err != io.EOF {
					t.error(peer, err)
				}
				continue
			} else {
				return reference, nil
			}
		}
	}
	return nil, errors.New("Could not get " + channel + " head from peers")
}

func (t *TCPNetwork) GetBlock(reference *Reference) (*Block, error) {
	for _, peer := range t.peers() {
		if len(peer) > 0 {
			address := net.JoinHostPort(peer, strconv.Itoa(PORT_GET_BLOCK))
			dialer := &net.Dialer{Timeout: t.DialTimeout}
			connection, err := dialer.Dial("tcp", address)
			if err != nil {
				t.error(peer, err)
				continue
			}
			defer connection.Close()
			writer := bufio.NewWriter(connection)
			if err := WriteDelimitedProtobuf(writer, reference); err != nil {
				t.error(peer, err)
				continue
			}
			reader := bufio.NewReader(connection)
			block := &Block{}
			if err := ReadDelimitedProtobuf(reader, block); err != nil {
				if err != io.EOF {
					t.error(peer, err)
				}
				continue
			} else {
				return block, nil
			}
		}
	}
	return nil, errors.New("Could not get " + reference.ChannelName + " block from peers")
}

func (t *TCPNetwork) Broadcast(channel *Channel, cache Cache, hash []byte, block *Block) error {
	var last error
	for _, peer := range t.peers() {
		last = nil
		if len(peer) > 0 {
			address := net.JoinHostPort(peer, strconv.Itoa(PORT_BROADCAST))
			dialer := &net.Dialer{Timeout: t.DialTimeout}
			connection, err := dialer.Dial("tcp", address)
			if err != nil {
				last = err
				t.error(peer, err)
				continue
			}
			defer connection.Close()
			writer := bufio.NewWriter(connection)
			reader := bufio.NewReader(connection)

			for {
				if err := WriteDelimitedProtobuf(writer, block); err != nil {
					return err
				}
				reference := &Reference{}
				if err := ReadDelimitedProtobuf(reader, reference); err != nil {
					if err == io.EOF {
						// Ignore
						break
					}
					return err
				}

				remote := reference.BlockHash
				if bytes.Equal(hash, remote) {
					// Broadcast accepted
					break
				} else {
					// Broadcast rejected
					referencedBlock, err := GetBlock(channel.Name, cache, t, remote)
					if err != nil {
						return err
					}

					if referencedBlock.Length == block.Length {
						// Option A: remote points to a different chain of the same length, next chain to get a block mined on top wins
						break
					} else if referencedBlock.Length > block.Length {
						// Option B: remote points to a longer chain
						go func() {
							if err := channel.Pull(cache, t); err != nil {
								fmt.Println(err)
							}
						}()
						return errors.New(ERROR_CHANNEL_OUT_OF_DATE)
						// TODO re-mine all dropped records into new blocks on top of new head
					} else {
						// Option C: remote points to a shorter chain, and cannot update because the chain cannot be verified or the host is missing some blocks
						block = referencedBlock
					}
				}
			}
		}
	}
	return last
}
