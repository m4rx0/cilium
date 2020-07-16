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

package kafka

import (
	"github.com/cilium/cilium/pkg/flowdebug"
	api "github.com/cilium/cilium/pkg/policy/api/kafka"

	"github.com/optiopay/kafka/proto"
	log "github.com/sirupsen/logrus"
)

// isTopicAPIKey returns true if kind is apiKey message type which contains a
// topic in its request.
func isTopicAPIKey(kind int16) bool {
	switch kind {
	case api.ProduceKey,
		api.FetchKey,
		api.OffsetsKey,
		api.MetadataKey,
		api.LeaderAndIsr,
		api.StopReplica,
		api.UpdateMetadata,
		api.OffsetCommitKey,
		api.OffsetFetchKey,
		api.CreateTopicsKey,
		api.DeleteTopicsKey,
		api.DeleteRecordsKey,
		api.OffsetForLeaderEpochKey,
		api.AddPartitionsToTxnKey,
		api.WriteTxnMarkersKey,
		api.TxnOffsetCommitKey,
		api.AlterReplicaLogDirsKey,
		api.DescribeLogDirsKey,
		api.CreatePartitionsKey:

		return true
	}
	return false
}

func matchNonTopicRequests(req *RequestMessage, rule *api.PortRule) bool {
	// matchNonTopicRequests() is called when
	// the kafka parser was not able to parse beyond the generic header.
	// This could be due to 2 sceanrios:
	// 1. It was a non-topic request
	// 2. The parser could not parse further even if there was a topic present.
	// For scenario 2, if topic is present, we need to return
	// false since topic can never be associated with this request kind.
	if rule.Topic != "" && isTopicAPIKey(req.kind) {
		return false
	}
	// TODO add functionality for parsing clientID GH-3097
	//if rule.ClientID != "" && rule.ClientID != req.GetClientID() {
	//	return false
	//}
	return true
}

func matchProduceReq(req *proto.ProduceReq, rule *api.PortRule) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchFetchReq(req *proto.FetchReq, rule *api.PortRule) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchOffsetReq(req *proto.OffsetReq, rule *api.PortRule) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchMetadataReq(req *proto.MetadataReq, rule *api.PortRule) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchOffsetCommitReq(req *proto.OffsetCommitReq, rule *api.PortRule) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchOffsetFetchReq(req *proto.OffsetFetchReq, rule *api.PortRule) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func (req *RequestMessage) RuleMatches(rule *api.PortRule) bool {
	if req == nil {
		return false
	}

	if flowdebug.Enabled() {
		log.Debugf("Matching Kafka request %s against rule %v", req.String(), *rule)
	}

	if !rule.CheckAPIKeyRole(req.kind) {
		return false
	}

	apiVersion, isWildcard := rule.GetAPIVersion()
	if !isWildcard && apiVersion != req.version {
		return false
	}

	// If the rule contains no additional conditionals, it is not required
	// to match into the request specific fields.
	if rule.Topic == "" && rule.ClientID == "" {
		return true
	}

	switch val := req.request.(type) {
	case *proto.ProduceReq:
		return matchProduceReq(val, rule)
	case *proto.FetchReq:
		return matchFetchReq(val, rule)
	case *proto.OffsetReq:
		return matchOffsetReq(val, rule)
	case *proto.MetadataReq:
		return matchMetadataReq(val, rule)
	case *proto.OffsetCommitReq:
		return matchOffsetCommitReq(val, rule)
	case *proto.OffsetFetchReq:
		return matchOffsetFetchReq(val, rule)
	case *proto.ConsumerMetadataReq:
		return true
	case nil:
		// This is the case when requests like
		// heartbeat,findcordinator, et al
		// are specified. They are not
		// associated with a topic, but we should
		// still check for ClientID present in request header.
		return matchNonTopicRequests(req, rule)
	default:
		// If all conditions have been met, allow the request
		return true
	}
}
