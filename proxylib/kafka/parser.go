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

type KafkaParser struct {
	connection *Connection
}

func (pf *KafkaParserFactory) Create(connection *Connection) interface{} {
	p := KafkaParser{connection: connection}
	return &p
}

func (p *KafkaParser) OnData(reply bool, reader *Reader) (OpType, int) {
	length := reader.Length()
	if length == 0 {
		return NOP, 0
	}

	framelength := 4          // account for the length field
	lenbuf := make([]byte, 8) // Peek the first eight bytes
	n, err := reader.PeekFull(lenbuf)
	if err == nil {
		framelength += int(binary.BigEndian.Uint32(lenbuf[:4]))
	} else {
		// Need more data
		return MORE, 8 - n
	}

	if reply {
		// Replies are always passed as-is. No need to parse them
		// on top of the frame length and correlation ID.
		correlationID := binary.BigEndian.Uint32(lenbuf[4:])
		p.connection.Log(cilium.EntryType_Response,
			&cilium.LogEntry_GenericL7{
				GenericL7: &cilium.L7LogEntry{
					Proto: parserName,
					Fields: map[string]string{
						"CorrelationID": strconv.Itoa(int(correlationID)),
					},
				},
			})
		return PASS, framelength
	}

	// Ask for more if full frame has not been received yet
	if length < framelength {
		// Not enough data, ask for more and try again
		return MORE, framelength - length
	}

	var req KafkaRequest
	req.RequestMessage, err = kafka.ReadRequest(reader)
	if err != nil {
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
		return PASS, framelength
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
	return DROP, framelength
}
