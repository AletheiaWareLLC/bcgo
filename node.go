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

package bcgo

const (
	ERROR_NO_SUCH_CHANNEL   = "No such channel: %s"
	ERROR_PAYLOAD_TOO_LARGE = "Payload too large: %s max: %s"
	ERROR_BLOCK_TOO_LARGE   = "Block too large: %s max: %s"
)

type Node interface {
	Account() Account
	Cache() Cache
	Network() Network
	AddChannel(Channel)
	Channel(string) (Channel, error)
	OpenChannel(string, func() Channel) Channel
	Channels() []Channel
	Write(uint64, Channel, []Identity, []*Reference, []byte) (*Reference, error)
}
