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
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"net"
	"strconv"
	"testing"
	"time"
)

type MockServer struct {
	ConnectListener   net.Listener
	BlockListener     net.Listener
	HeadListener      net.Listener
	BroadcastListener net.Listener
}

func makeMockServer(t *testing.T) *MockServer {
	t.Helper()
	cl, err := net.Listen("tcp", net.JoinHostPort("localhost", strconv.Itoa(bcgo.PORT_CONNECT)))
	if err != nil {
		t.Fatalf("Could not make listener: '%s'", err)
	}
	bl, err := net.Listen("tcp", net.JoinHostPort("localhost", strconv.Itoa(bcgo.PORT_GET_BLOCK)))
	if err != nil {
		t.Fatalf("Could not make listener: '%s'", err)
	}
	hl, err := net.Listen("tcp", net.JoinHostPort("localhost", strconv.Itoa(bcgo.PORT_GET_HEAD)))
	if err != nil {
		t.Fatalf("Could not make listener: '%s'", err)
	}
	bcl, err := net.Listen("tcp", net.JoinHostPort("localhost", strconv.Itoa(bcgo.PORT_BROADCAST)))
	if err != nil {
		t.Fatalf("Could not make listener: '%s'", err)
	}
	return &MockServer{
		ConnectListener:   cl,
		BlockListener:     bl,
		HeadListener:      hl,
		BroadcastListener: bcl,
	}
}

func unmakeMockServer(t *testing.T, server *MockServer) {
	t.Helper()
	server.ConnectListener.Close()
	server.BlockListener.Close()
	server.HeadListener.Close()
	server.BroadcastListener.Close()
}

func makeConnectListener(t *testing.T, listener net.Listener, expected, reply []byte) {
	t.Helper()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			t.Fatalf("Could not accept connection: '%s'", err)
		}
		defer connection.Close()
		writer := bufio.NewWriter(connection)
		reader := bufio.NewReader(connection)
		buffer := make([]byte, 32)
		n, err := reader.Read(buffer[:])
		testinggo.AssertNoError(t, err)
		request := buffer[:n]
		if !bytes.Equal(request, expected) {
			t.Fatalf("Unrecognized request: expected '%s', got '%s'", string(expected), string(request))
		}
		n, err = writer.Write(reply)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, writer.Flush())
	}()
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

func TestTcpNetworkConnect(t *testing.T) {
	t.Run("NoServer", func(t *testing.T) {
		network := bcgo.NewTCPNetwork()
		network.DialTimeout = time.Second // Reduce timeout so test fails quicker
		err := network.Connect("FAKEPEER", []byte(""))
		if err == nil {
			t.Fatalf("Expected error")
		}
	})
	t.Run("Success", func(t *testing.T) {
		network := bcgo.NewTCPNetwork()

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		// Connect Listener
		makeConnectListener(t, server.ConnectListener, []byte("hello"), []byte("hi"))

		testinggo.AssertNoError(t, network.Connect("localhost", []byte("hello")))
	})
}

func TestTcpNetworkBlock(t *testing.T) {
	t.Run("NoServer", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := bcgo.NewTCPNetwork("localhost")
		_, err := bcgo.GetBlock(channel.Name, cache, network, []byte("FAKEHASH"))
		testinggo.AssertError(t, "Could not get TEST block from peers", err)
	})
	t.Run("Success", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := bcgo.NewTCPNetwork("localhost")

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		block := makeBlock(t, 1234)
		hash := makeHash(t, block)

		// Block Listener
		makeBlockListener(t, server.BlockListener, hash, block)

		b, err := bcgo.GetBlock(channel.Name, cache, network, hash)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, block, b)
	})
}

func TestTcpNetworkHead(t *testing.T) {
	t.Run("NoServer", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := bcgo.NewTCPNetwork("localhost")
		_, err := bcgo.GetHeadReference(channel.Name, cache, network)
		testinggo.AssertError(t, "Could not get TEST head from peers", err)
	})
	t.Run("Success", func(t *testing.T) {
		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := bcgo.NewTCPNetwork("localhost")

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		block := makeBlock(t, 1234)
		hash := makeHash(t, block)

		// Head Listener
		makeHeadListener(t, server.HeadListener, hash)

		h, err := bcgo.GetHeadReference(channel.Name, cache, network)
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
		network := bcgo.NewTCPNetwork("localhost")
		cache.PutBlock(hash, block)
		channel.Head = hash

		testinggo.AssertMatchesError(t, "dial tcp .*:23232: connect: connection refused", channel.Push(cache, network))
	})
	t.Run("LocalRemoteEqualLength", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)

		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := bcgo.NewTCPNetwork("localhost")
		cache.PutBlock(hash1, block1)
		channel.Head = hash1

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

		testinggo.AssertNoError(t, channel.Push(cache, network))
	})
	t.Run("LocalLongerThanRemote", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)

		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := bcgo.NewTCPNetwork("localhost")
		block2 := makeLinkedBlock(t, 5678, hash1, block1)
		hash2 := makeHash(t, block2)
		block3 := makeLinkedBlock(t, 9012, hash2, block2)
		hash3 := makeHash(t, block3)

		cache.PutBlock(hash1, block1)
		cache.PutBlock(hash2, block2)
		cache.PutBlock(hash3, block3)
		channel.Head = hash3

		server := makeMockServer(t)
		defer unmakeMockServer(t, server)

		//Broadcast Listener
		makeBroadcastListener(t, server.BroadcastListener, map[string][]byte{
			block3.String(): hash2, // 3 missing 2
			block2.String(): hash1, // 2 missing 1
			block1.String(): hash3, // 1 missing none
		})

		testinggo.AssertNoError(t, channel.Push(cache, network))
	})
	t.Run("RemoteLongerThanLocal", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)

		channel := makeMockChannel(t)
		cache := bcgo.NewMemoryCache(10)
		network := bcgo.NewTCPNetwork("localhost")
		cache.PutBlock(hash1, block1)
		channel.Head = hash1

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

		testinggo.AssertError(t, bcgo.ERROR_CHANNEL_OUT_OF_DATE, channel.Push(cache, network))
	})
}
