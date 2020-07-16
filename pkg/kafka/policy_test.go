// Copyright 2017 Authors of Cilium
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

// +build !privileged_tests

package kafka

import (
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/policy/api/kafka"

	"github.com/optiopay/kafka/proto"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type kafkaTestSuite struct{}

var _ = Suite(&kafkaTestSuite{})

var (
	messages = make([]*proto.Message, 100)
)

func (k *kafkaTestSuite) SetUpTest(c *C) {
	for i := range messages {
		messages[i] = &proto.Message{
			Offset: int64(i),
			Crc:    uint32(i),
			Key:    nil,
			Value:  []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur.`),
		}

	}
}

// MatchesRule validates the Kafka request message against the provided list of
// rules. The function will return true if the policy allows the message,
// otherwise false is returned.
func (req *RequestMessage) MatchesRule(rules []kafka.PortRule) bool {
	topics := req.GetTopics()
	// Maintain a map of all topics in the request.
	// We should allow the request only if all topics are
	// allowed by the list of rules.
	reqTopicsMap := make(map[string]bool, len(topics))
	for _, topic := range topics {
		reqTopicsMap[topic] = true
	}

	for _, rule := range rules {
		if rule.Topic == "" || len(topics) == 0 {
			if req.RuleMatches(&rule) {
				return true
			}
		} else if reqTopicsMap[rule.Topic] {
			if req.RuleMatches(&rule) {
				delete(reqTopicsMap, rule.Topic)
				if len(reqTopicsMap) == 0 {
					return true
				}
			}
		}
	}
	return false
}

func (k *kafkaTestSuite) TestProduceRequest(c *C) {
	req := &proto.ProduceReq{
		CorrelationID: 241,
		ClientID:      "test",
		Compression:   proto.CompressionNone,
		RequiredAcks:  proto.RequiredAcksAll,
		Timeout:       time.Second,
		Topics: []proto.ProduceReqTopic{
			{
				Name: "foo",
				Partitions: []proto.ProduceReqPartition{
					{
						ID:       0,
						Messages: messages,
					},
				},
			},
			{
				Name: "bar",
				Partitions: []proto.ProduceReqPartition{
					{
						ID:       0,
						Messages: messages,
					},
				},
			},
		},
	}

	reqMsg := RequestMessage{
		request: req,
	}

	// empty rules should match nothing
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{}), Equals, false)

	// wildcard rule matches everything
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{{}}), Equals, true)

	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{
		{Topic: "foo"},
	}), Equals, false)
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{
		{Topic: "foo"}, {Topic: "bar"},
	}), Equals, true)
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{
		{Topic: "foo"}, {Topic: "baz"},
	}), Equals, false)
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{
		{Topic: "baz"}, {Topic: "foo2"},
	}), Equals, false)
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{
		{Topic: "bar"}, {Topic: "foo"},
	}), Equals, true)

	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{
		{Topic: "bar"}, {Topic: "foo"}, {Topic: "baz"}}), Equals, true)

}

func (k *kafkaTestSuite) TestUnknownRequest(c *C) {
	reqMsg := RequestMessage{kind: 18} // ApiVersions request

	// Empty rule should disallow
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{}), Equals, false)

	// Whitelisting of unknown message
	rule1 := kafka.PortRule{APIKey: "metadata"}
	c.Assert(rule1.Sanitize(), IsNil)
	rule2 := kafka.PortRule{APIKey: "apiversions"}
	c.Assert(rule2.Sanitize(), IsNil)
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{rule1, rule2}), Equals, true)

	reqMsg = RequestMessage{kind: 19}
	c.Assert(reqMsg.MatchesRule([]kafka.PortRule{rule1, rule2}), Equals, false)
}
