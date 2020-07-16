// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kafka

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	. "github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/kafka"
	kafka_api "github.com/cilium/cilium/pkg/policy/api/kafka"
	cilium "github.com/cilium/proxy/go/cilium/api"

	log "github.com/sirupsen/logrus"
)

const (
	parserName = "kafka"
)

type KafkaRule struct {
	kafka_api.PortRule
}

type KafkaRequest struct {
	*kafka.RequestMessage
	// Maintain a map of all topics in the request.
	// We should allow the request only if all topics are
	// allowed by the list of rules.
	topics map[string]struct{}
}

// Matches returns true if the HeaderRule matches
func (rule *KafkaRule) Matches(data interface{}) bool {
	req, ok := data.(KafkaRequest)
	if !ok {
		log.Warning("Matches() called with type other than KafkaRequest")
		return false
	}
	if rule.Topic == "" || len(req.topics) == 0 {
		return req.RuleMatches(&rule.PortRule)
	} else if _, exists := req.topics[rule.Topic]; exists && req.RuleMatches(&rule.PortRule) {
		delete(req.topics, rule.Topic)
		return len(req.topics) == 0
	}
	return false
}

// KafkaRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func KafkaRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetL7Rules()
	rules := make([]L7NetworkPolicyRule, 0, len(allowRules))
	for _, l7Rule := range allowRules {
		var kr KafkaRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "role":
				kr.Role = v
			case "apikey":
				kr.APIKey = v
			case "apiversion":
				kr.APIVersion = v
			case "clientid":
				kr.ClientID = v
			case "topic":
				kr.Topic = v
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		err := kr.PortRule.Sanitize()
		if err != nil {
			panic("invalid Kafka rule")
		}
		rules = append(rules, &kr)
	}
	return rules
}

type KafkaParserFactory struct{}

var kafkaParserFactory *KafkaParserFactory

func init() {
	log.Info("init(): Registering kafkaParserFactory")
	RegisterParserFactory(parserName, kafkaParserFactory)
	RegisterL7RuleParser(parserName, KafkaRuleParser)
}

// This would be simpler if integrated into proxylib.Connection as on this side we can not touch the
// 'buf' at all.
type Reader struct {
	buf   [][]byte
	slice int
	index int
	count int
}

func (r *Reader) reset() {
	r.slice = 0
	r.index = 0
	r.count = 0
}

func (r *Reader) DecodeUint32() uint32 {
	b := make([]byte, 4)
	n, err := io.ReadFull(r, b)
	if err != nil {
		if flowdebug.Enabled() {
			log.WithError(err).Debug("io.ReadFull() failed")
		}
		return 0
	}
	if n != 4 {
		if flowdebug.Enabled() {
			log.Debugf("io.ReadFull() read != 4 bytes: %d", n)
		}
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *Reader) Missing() int {
	// Not enough data, ask for more and try again
	read := r.count // how much read so far
	if read >= 4 {
		have := read - 4 // excluding the length field
		// Have the length field, request the number of bytes needed
		r.reset()                     // reset the reader to read the length
		want := int(r.DecodeUint32()) // not including the length itself
		if want > have {
			return want - have
		}
		return 1 // likely protocol error (invalid length)
	}
	return 4 - read // enough for the length field
}

func (r *Reader) Read(p []byte) (n int, err error) {
	n = 0
	l := len(p)
	slices := len(r.buf)
	for n < l && r.slice < slices {
		nc := copy(p[n:], r.buf[r.slice][r.index:])
		if nc == len(r.buf[r.slice][r.index:]) {
			// next slice please
			r.slice++
			r.index = 0
		} else {
			// move ahead in the same slice
			r.index += nc
		}
		n += nc
	}
	if n == 0 {
		return 0, io.EOF
	}
	r.count += n
	return n, nil
}

type KafkaParser struct {
	connection *Connection
}

func (pf *KafkaParserFactory) Create(connection *Connection) Parser {
	p := KafkaParser{connection: connection}
	return &p
}

func (p *KafkaParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {
	reader := &Reader{buf: dataArray}

	length := 0
	for i := 0; i < len(dataArray); i++ {
		length += len(dataArray[i])
	}
	if length == 0 {
		return NOP, 0
	}

	if reply {
		// Replies are parsed but always passed as-is.
		// This allows the error responses to be injected on frame boundaries.
		resp, err := kafka.ReadResponse(reader)
		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				// Not enough data, ask for more and try again
				return MORE, reader.Missing()
			}
			if flowdebug.Enabled() {
				log.WithError(err).Warning("Unable to parse Kafka response; closing Kafka connection")
			}
			return ERROR, int(ERROR_INVALID_FRAME_TYPE)
		}
		p.connection.Log(cilium.EntryType_Response,
			&cilium.LogEntry_GenericL7{
				GenericL7: &cilium.L7LogEntry{
					Proto: parserName,
					Fields: map[string]string{
						"CorrelationID": strconv.Itoa(int(resp.GetCorrelationID())),
					},
				},
			})
		return PASS, int(reader.count)
	}

	var req KafkaRequest
	var err error
	req.RequestMessage, err = kafka.ReadRequest(reader)
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			// Not enough data, ask for more and try again
			return MORE, reader.Missing()
		}
		if flowdebug.Enabled() {
			log.WithError(err).Warning("Unable to parse Kafka request; closing Kafka connection")
		}
		return ERROR, int(ERROR_INVALID_FRAME_TYPE)
	}

	topics := req.GetTopics()
	// Maintain a map of all topics in the request.
	// We should allow the request only if all topics are
	// allowed by the list of rules.
	req.topics = make(map[string]struct{}, len(topics))
	for _, topic := range topics {
		req.topics[topic] = struct{}{}
	}
	logEntry := &cilium.LogEntry_GenericL7{
		GenericL7: &cilium.L7LogEntry{
			Proto: parserName,
			Fields: map[string]string{
				"APIVersion":    strconv.Itoa(int(req.GetVersion())),
				"APIKey":        kafka_api.ApiKeyToString(req.GetAPIKey()),
				"CorrelationID": strconv.Itoa(int(req.GetCorrelationID())),
				"Topics":        strings.Join(topics, ","),
			},
		},
	}
	if p.connection.Matches(req) {
		p.connection.Log(cilium.EntryType_Request, logEntry)
		return PASS, int(reader.count)
	}

	resp, err := req.CreateAuthErrorResponse()
	if err != nil {
		logEntry.GenericL7.Fields["status"] = strconv.Itoa(int(kafka.ErrInvalidMessage))
		if flowdebug.Enabled() {
			log.WithError(err).Warning("Unable to create Kafka response")
		}
	} else {
		logEntry.GenericL7.Fields["status"] = strconv.Itoa(int(kafka.ErrTopicAuthorizationFailed))
		// inject response
		p.connection.Inject(!reply, resp.GetRaw())
	}

	p.connection.Log(cilium.EntryType_Denied, logEntry)
	return DROP, int(reader.count)
}
