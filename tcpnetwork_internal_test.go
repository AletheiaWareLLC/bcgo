/*
 * Copyright 2020 Aletheia Ware LLC
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
	"testing"
)

func TestTCPNetwork_Peers(t *testing.T) {
	network := NewTCPNetwork()
	peers := network.peers()
	if len(peers) != 0 {
		t.Errorf("Incorrect Peers: Expected none, got '%v'", peers)
	}

	network.AddPeer("peer0")
	peers = network.peers()
	if len(peers) != 1 || peers[0] != "peer0" {
		t.Errorf("Incorrect Peers: Expected '[peer0]', got '%v'", peers)
	}
	network.AddPeer("peer1")
	network.error("peer1", errors.New("Foobar"))

	peers = network.peers()
	if len(peers) != 2 || peers[0] != "peer0" || peers[1] != "peer1" {
		t.Errorf("Incorrect Peers: Expected '[peer0 peer1]', got '%v'", peers)
	}

	network.AddPeer("peer2")
	network.error("peer2", errors.New("Foobar1"))
	network.error("peer2", errors.New("Foobar2"))

	// Peers should return the least erroneous peers ie. result should not contain peer2
	peers = network.peers()
	if len(peers) != 2 || peers[0] != "peer0" || peers[1] != "peer1" {
		t.Errorf("Incorrect Peers: Expected '[peer0 peer1]', got '%v'", peers)
	}

	for i := 0; i <= MAX_TCP_ERRORS; i++ {
		network.error("peer0", fmt.Errorf("Foobar%d", i))
	}
	if _, ok := network.Peers["peer0"]; ok {
		t.Errorf("Incorrect Peers: Expected 'peer0' to be removed due to excessive errors")
	}
	// Peers should return the least erroneous peers ie. results should not contain peer0
	peers = network.peers()
	if len(peers) != 2 || peers[0] != "peer1" || peers[1] != "peer2" {
		t.Errorf("Incorrect Peers: Expected '[peer1 peer2]', got '%v'", peers)
	}
}
