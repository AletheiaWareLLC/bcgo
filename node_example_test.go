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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"io/ioutil"
	"log"
)

func ExampleNode() {
	// Create temp directory
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal("Could not create temp cache dir:", err)
	}

	// Create file cache
	cache, err := bcgo.NewFileCache(dir)
	if err != nil {
		log.Fatal("Could not create file cache:", err)
	}

	channel := &bcgo.Channel{
		Name: "Example",
	}

	// Write record to cache
	_, err = bcgo.WriteRecord(channel.Name, cache, &bcgo.Record{
		Payload: []byte("Example!"),
	})
	if err != nil {
		log.Fatal("Could not write record:", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal("Could not generate private key:", err)
	}

	// Create node
	node := &bcgo.Node{
		Alias: "ExampleNode",
		Key:   privateKey,
		Cache: cache,
	}

	// Mine all records in cache
	hash, block, err := node.Mine(channel, bcgo.THRESHOLD_G, nil)
	if err != nil {
		log.Fatal("Could not mine:", err)
	}

	fmt.Println(base64.RawURLEncoding.EncodeToString(hash))
	fmt.Println(block)
}

func ExampleNode_Network() {
	// Create temp directory
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal("Could not create temp cache dir:", err)
	}

	// Create file cache
	cache, err := bcgo.NewFileCache(dir)
	if err != nil {
		log.Fatal("Could not create file cache:", err)
	}

	// Create network of peers
	network := &bcgo.TcpNetwork{
		Peers: []string{
			"example.com",
		},
	}

	channel := &bcgo.Channel{
		Name: "Example",
	}

	// Write record to cache
	_, err = bcgo.WriteRecord(channel.Name, cache, &bcgo.Record{
		Payload: []byte("Example!"),
	})
	if err != nil {
		log.Fatal("Could not write record:", err)
	}

	// Get private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal("Could not get private key:", err)
	}

	// Create node
	node := &bcgo.Node{
		Alias: "ExampleNode",
		Key:   privateKey,
		Cache: cache,
	}

	// Mine all records in cache
	hash, block, err := node.Mine(channel, bcgo.THRESHOLD_G, nil)
	if err != nil {
		log.Fatal("Could not mine:", err)
	}

	// Push update to network
	if err := channel.Push(cache, network); err != nil {
		log.Fatal("Could not push:", err)
	}

	fmt.Println(base64.RawURLEncoding.EncodeToString(hash))
	fmt.Println(block)
}
