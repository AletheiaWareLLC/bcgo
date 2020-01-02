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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	PORT_GET_BLOCK = 22222
	PORT_GET_HEAD  = 22322
	PORT_BROADCAST = 23232

	ERROR_CHANNEL_OUT_OF_DATE = "Channel out of date"
)

type TcpNetwork struct {
	Peers []string
}

func (t *TcpNetwork) GetHead(channel string) (*Reference, error) {
	for _, peer := range t.Peers {
		if len(peer) > 0 {
			address := peer + ":" + strconv.Itoa(PORT_GET_HEAD)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				fmt.Println(err)
				continue
			}
			defer connection.Close()
			writer := bufio.NewWriter(connection)
			if err := WriteDelimitedProtobuf(writer, &Reference{
				ChannelName: channel,
			}); err != nil {
				fmt.Println(err)
				continue
			}
			reader := bufio.NewReader(connection)
			reference := &Reference{}
			if err := ReadDelimitedProtobuf(reader, reference); err != nil {
				if err != io.EOF {
					fmt.Println(err)
				}
				continue
			} else {
				fmt.Printf("Fetched %s head from %s\n", channel, peer)
				return reference, nil
			}
		}
	}
	return nil, errors.New("Could not get " + channel + " head from peers")
}

func (t *TcpNetwork) GetBlock(reference *Reference) (*Block, error) {
	for _, peer := range t.Peers {
		if len(peer) > 0 {
			address := peer + ":" + strconv.Itoa(PORT_GET_BLOCK)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				fmt.Println(err)
				continue
			}
			defer connection.Close()
			writer := bufio.NewWriter(connection)
			if err := WriteDelimitedProtobuf(writer, reference); err != nil {
				fmt.Println(err)
				continue
			}
			reader := bufio.NewReader(connection)
			block := &Block{}
			if err := ReadDelimitedProtobuf(reader, block); err != nil {
				if err != io.EOF {
					fmt.Println(err)
				}
				continue
			} else {
				if reference.BlockHash != nil {
					fmt.Printf("Fetched %s block %s from %s\n", reference.ChannelName, base64.RawURLEncoding.EncodeToString(reference.BlockHash), peer)
				} else {
					fmt.Printf("Fetched %s record %s from %s\n", reference.ChannelName, base64.RawURLEncoding.EncodeToString(reference.RecordHash), peer)
				}
				return block, nil
			}
		}
	}
	return nil, errors.New("Could not get " + reference.ChannelName + " block from peers")
}

func (t *TcpNetwork) Broadcast(channel *Channel, cache Cache, hash []byte, block *Block) error {
	for _, peer := range t.Peers {
		if len(peer) > 0 {
			address := peer + ":" + strconv.Itoa(PORT_BROADCAST)
			connection, err := net.Dial("tcp", address)
			if err != nil {
				return err
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
					return err
				}

				remote := reference.BlockHash
				if bytes.Equal(hash, remote) {
					// Broadcast accepted
					fmt.Printf("Broadcast %s block %s to %s\n", channel.GetName(), base64.RawURLEncoding.EncodeToString(hash), peer)
					break
				} else {
					fmt.Println(peer, base64.RawURLEncoding.EncodeToString(remote))

					// Broadcast rejected
					referencedBlock, err := GetBlock(channel.GetName(), cache, t, remote)
					if err != nil {
						return err
					}
					fmt.Println(referencedBlock)

					if referencedBlock.Length == block.Length {
						// Option A: remote points to a different chain of the same length, next chain to get a block mined on top wins
						break
					} else if referencedBlock.Length > block.Length {
						// Option B: remote points to a longer chain
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
	return nil
}
