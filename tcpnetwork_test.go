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
	"bufio"
	"bytes"
	"encoding/base64"
	//"errors"
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"net"
	"strconv"
	"testing"
)

type MockServer struct {
	BlockListener     net.Listener
	HeadListener      net.Listener
	BroadcastListener net.Listener
}

func makeMockServer(t *testing.T) *MockServer {
	t.Helper()
	bl, err := net.Listen("tcp", "localhost:"+strconv.Itoa(bcgo.PORT_GET_BLOCK))
	if err != nil {
		t.Fatalf("Could not make listener: '%s'", err)
	}
	hl, err := net.Listen("tcp", "localhost:"+strconv.Itoa(bcgo.PORT_GET_HEAD))
	if err != nil {
		t.Fatalf("Could not make listener: '%s'", err)
	}
	bcl, err := net.Listen("tcp", "localhost:"+strconv.Itoa(bcgo.PORT_BROADCAST))
	if err != nil {
		t.Fatalf("Could not make listener: '%s'", err)
	}
	return &MockServer{
		BlockListener:     bl,
		HeadListener:      hl,
		BroadcastListener: bcl,
	}
}

func unmakeMockServer(t *testing.T, server *MockServer) {
	t.Helper()
	server.BlockListener.Close()
	server.HeadListener.Close()
	server.BroadcastListener.Close()
}

func makeBlockListener(t *testing.T, listener net.Listener, expected []byte, reply *bcgo.Block) {
	t.Helper()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			t.Fatalf("Could not accept connection: '%s'", err)
		}
		defer connection.Close()
		writer := bufio.NewWriter(connection)
		reader := bufio.NewReader(connection)
		request := &bcgo.Reference{}
		if err := bcgo.ReadDelimitedProtobuf(reader, request); err != nil {
			t.Fatalf("Could not read from connection: '%s'", err)
		}
		fmt.Println(request)
		if !bytes.Equal(request.BlockHash, expected) {
			t.Fatalf("Unrecognized hash: '%s'", base64.RawURLEncoding.EncodeToString(request.BlockHash))
		}
		if err := bcgo.WriteDelimitedProtobuf(writer, reply); err != nil {
			t.Fatalf("Could not write to connection: '%s'", err)
		}
	}()
}

func makeHeadListener(t *testing.T, listener net.Listener, hash []byte) {
	t.Helper()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			t.Fatalf("Could not accept connection: '%s'", err)
		}
		defer connection.Close()
		writer := bufio.NewWriter(connection)
		reader := bufio.NewReader(connection)

		request := &bcgo.Reference{}
		if err := bcgo.ReadDelimitedProtobuf(reader, request); err != nil {
			t.Fatalf("Could not read from connection: '%s'", err)
		}

		fmt.Println(request)

		if "TEST" != request.ChannelName {
			t.Fatalf("Incorrect channel; expected '%s', got '%s'", "TEST", request.ChannelName)
		}

		if err := bcgo.WriteDelimitedProtobuf(writer, &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}); err != nil {
			t.Fatalf("Could not write to connection: '%s'", err)
		}
	}()
}

func makeBroadcastListener(t *testing.T, listener net.Listener, replies map[string][]byte) {
	t.Helper()
	go func() {
		fmt.Println("Broadcast Listener")
		for k, v := range replies {
			fmt.Println("Map: " + k + " : " + base64.RawURLEncoding.EncodeToString(v))
		}

		connection, err := listener.Accept()
		if err != nil {
			t.Fatalf("Could not accept connection: '%s'", err)
		}
		defer connection.Close()
		writer := bufio.NewWriter(connection)
		reader := bufio.NewReader(connection)

		for i := 0; i < len(replies); i++ {
			request := &bcgo.Block{}
			if err := bcgo.ReadDelimitedProtobuf(reader, request); err != nil {
				t.Fatalf("Could not read from connection: '%s'", err)
			}

			fmt.Println("Received Broadcast: " + request.String())

			reply, ok := replies[request.String()]
			if !ok {
				t.Fatalf("Unexpected request: '%s'", request.String())
			}

			fmt.Println("Replying: " + base64.RawURLEncoding.EncodeToString(reply))

			if err := bcgo.WriteDelimitedProtobuf(writer, &bcgo.Reference{
				ChannelName: "TEST",
				BlockHash:   reply,
			}); err != nil {
				t.Fatalf("Could not write to connection: '%s'", err)
			}
		}
	}()
}

func TestTcpNetworkBlock(t *testing.T) {
	t.Run("NoServer", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}
		_, err := bcgo.GetBlock(channel.GetName(), cache, network, []byte("FAKEHASH"))
		testinggo.AssertError(t, "Could not get TEST block from peers", err)
	})
	t.Run("Success", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		block := makeBlock(t, 1234)
		hash := makeHash(t, block)

		// Block Listener
		makeBlockListener(t, server.BlockListener, hash, block)

		b, err := bcgo.GetBlock(channel.GetName(), cache, network, hash)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, block, b)
	})
}

func TestTcpNetworkHead(t *testing.T) {
	t.Run("NoServer", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}
		_, err := bcgo.GetHeadReference(channel.GetName(), cache, network)
		testinggo.AssertError(t, "Could not get TEST head from peers", err)
	})
	t.Run("Success", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		block := makeBlock(t, 1234)
		hash := makeHash(t, block)

		// Head Listener
		makeHeadListener(t, server.HeadListener, hash)

		h, err := bcgo.GetHeadReference(channel.GetName(), cache, network)
		testinggo.AssertNoError(t, err)
		if !bytes.Equal(hash, h.BlockHash) {
			t.Fatalf("Incorrect head; expected '%s', got '%s'", base64.RawURLEncoding.EncodeToString(hash), base64.RawURLEncoding.EncodeToString(h.BlockHash))
		}
	})
}

func TestTcpNetworkBroadcast(t *testing.T) {
	t.Run("NoServer", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)

		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}
		cache.PutBlock(hash, block)
		channel.SetHead(hash)

		testinggo.AssertError(t, "dial tcp 127.0.0.1:23232: connect: connection refused", bcgo.Push(channel, cache, network))
	})
	t.Run("LocalRemoteEqualLength", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)

		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}
		cache.PutBlock(hash1, block1)
		channel.SetHead(hash1)

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		netBlock1 := makeBlock(t, 2345)
		netHash1 := makeHash(t, netBlock1)

		//Block Listener
		makeBlockListener(t, server.BlockListener, netHash1, netBlock1)

		//Broadcast Listener
		makeBroadcastListener(t, server.BroadcastListener, map[string][]byte{
			block1.String(): netHash1,
		})

		testinggo.AssertNoError(t, bcgo.Push(channel, cache, network))
	})
	t.Run("LocalLongerThanRemote", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)

		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}
		block2 := makeLinkedBlock(t, 5678, hash1, block1)
		hash2 := makeHash(t, block2)
		block3 := makeLinkedBlock(t, 9012, hash2, block2)
		hash3 := makeHash(t, block3)

		cache.PutBlock(hash1, block1)
		cache.PutBlock(hash2, block2)
		cache.PutBlock(hash3, block3)
		channel.SetHead(hash3)

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		//Broadcast Listener
		makeBroadcastListener(t, server.BroadcastListener, map[string][]byte{
			block3.String(): hash2, // 3 missing 2
			block2.String(): hash1, // 2 missing 1
			block1.String(): hash3, // 1 missing none
		})

		testinggo.AssertNoError(t, bcgo.Push(channel, cache, network))
	})
	t.Run("RemoteLongerThanLocal", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)

		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := &bcgo.TcpNetwork{
			Peers: []string{
				"localhost",
			},
		}
		cache.PutBlock(hash1, block1)
		channel.SetHead(hash1)

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		netBlock1 := makeBlock(t, 1234)
		netHash1 := makeHash(t, netBlock1)
		netBlock2 := makeLinkedBlock(t, 5678, netHash1, netBlock1)
		netHash2 := makeHash(t, netBlock2)

		//Block Listener
		makeBlockListener(t, server.BlockListener, netHash2, netBlock2)

		//Broadcast Listener
		makeBroadcastListener(t, server.BroadcastListener, map[string][]byte{
			block1.String(): netHash2,
		})

		testinggo.AssertError(t, bcgo.ERROR_CHANNEL_OUT_OF_DATE, bcgo.Push(channel, cache, network))
	})
}
