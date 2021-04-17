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

package node_test

import (
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/account"
	"aletheiaware.com/bcgo/cache"
	"aletheiaware.com/bcgo/channel"
	"aletheiaware.com/bcgo/network"
	"aletheiaware.com/bcgo/node"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"time"
)

func ExampleNode() {
	// Create temp directory
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal("Could not create temp cache dir:", err)
	}

	// Create file cache
	cache, err := cache.NewFileSystem(dir)
	if err != nil {
		log.Fatal("Could not create file cache:", err)
	}

	channel := channel.New("Example")

	// Write record to cache
	_, err = bcgo.WriteRecord(channel.Name(), cache, &bcgo.Record{
		Payload: []byte("Example!"),
	})
	if err != nil {
		log.Fatal("Could not write record:", err)
	}

	// Create account
	account, err := account.GenerateRSA("ExampleNode")
	if err != nil {
		log.Fatal("Could not generate account:", err)
	}

	// Create node
	node := node.New(
		account,
		cache,
		nil,
	)

	// Mine all records in cache
	hash, block, err := bcgo.Mine(node, channel, bcgo.THRESHOLD_G, nil)
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
	cache, err := cache.NewFileSystem(dir)
	if err != nil {
		log.Fatal("Could not create file cache:", err)
	}

	// Create network of peers
	network := network.NewTCP("example.com")
	network.DialTimeout = time.Second
	network.GetTimeout = time.Second

	channel := channel.New("Example")

	// Write record to cache
	_, err = bcgo.WriteRecord(channel.Name(), cache, &bcgo.Record{
		Payload: []byte("Example!"),
	})
	if err != nil {
		log.Fatal("Could not write record:", err)
	}

	// Create account
	account, err := account.GenerateRSA("ExampleNode")
	if err != nil {
		log.Fatal("Could not generate account:", err)
	}

	// Create node
	node := node.New(
		account,
		cache,
		nil,
	)

	// Mine all records in cache
	hash, block, err := bcgo.Mine(node, channel, bcgo.THRESHOLD_G, nil)
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
