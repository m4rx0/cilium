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

package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	ErrNilMap                  = errors.New("Nil map")
	ErrUnknownNamedPortIngress = errors.New("Unknown named port (ingress)")
	ErrUnknownNamedPort        = errors.New("Unknown named port")
	ErrIncompatibleProtocol    = errors.New("Incompatible protocol")
	ErrNamedPortIsZero         = errors.New("Named port is zero")
	ErrDuplicateNamedPorts     = errors.New("duplicate named ports")
)

type PortProto struct {
	Port  uint16 // non-0
	Proto uint8  // 0 for any
}

type NamedPortMap map[string]PortProto

// PortProtoSet is a set of unique PortProto values
type PortProtoSet map[PortProto]struct{}

func (pps PortProtoSet) Equal(other PortProtoSet) bool {
	if len(pps) != len(other) {
		return false
	}

	for port := range pps {
		if _, exists := other[port]; !exists {
			return false
		}
	}
	return true
}

// NamedPortMultiMap may have multiple entries for a name if multiple PODs
// define the same name with different values.
type NamedPortMultiMap map[string]PortProtoSet

func (npm NamedPortMultiMap) Equal(other NamedPortMultiMap) bool {
	if len(npm) != len(other) {
		return false
	}
	for name, ports := range npm {
		if otherPorts, exists := other[name]; !exists || !ports.Equal(otherPorts) {
			return false
		}
	}
	return true
}

func ValidatePortName(name string) (string, error) {
	if !iana.IsSvcName(name) { // Port names are formatted as IANA Service Names
		return "", fmt.Errorf("Invalid port name \"%s\", not using as a named port", name)
	}
	return strings.ToLower(name), nil // Normalize for case-insensitive comparison
}

func ParsePortProto(port int, protocol string) (pp PortProto, err error) {
	var u8p u8proto.U8proto
	if protocol == "" {
		u8p = u8proto.TCP // K8s ContainerPort protocol defaults to TCP
	} else {
		var err error
		u8p, err = u8proto.ParseProtocol(protocol)
		if err != nil {
			return pp, err
		}
	}
	if port < 1 || port > 65535 {
		if port == 0 {
			return pp, ErrNamedPortIsZero
		}
		return pp, fmt.Errorf("Port number %d out of 16-bit range", port)
	}
	return PortProto{
		Proto: uint8(u8p),
		Port:  uint16(port),
	}, nil
}

func (npm NamedPortMap) AddPort(name string, port int, protocol string) error {
	name, err := ValidatePortName(name)
	if err != nil {
		return err
	}
	pp, err := ParsePortProto(port, protocol)
	if err != nil {
		return err
	}
	npm[name] = pp
	return nil
}

// NamedPortMap abstracts different maps that implement GetNamedPort method
type NamedPortsMap interface {
	GetNamedPort(name string, proto uint8) (port uint16, err error)
}

func (npm NamedPortMap) GetNamedPort(name string, proto uint8) (uint16, error) {
	if npm == nil {
		return 0, ErrNilMap
	}
	pp, ok := npm[name]
	if !ok {
		return 0, ErrUnknownNamedPortIngress
	}
	if pp.Proto != 0 && proto != pp.Proto {
		return 0, ErrIncompatibleProtocol
	}
	if pp.Port == 0 {
		return 0, ErrNamedPortIsZero
	}
	return pp.Port, nil
}

func (npm NamedPortMultiMap) GetNamedPort(name string, proto uint8) (uint16, error) {
	if npm == nil {
		return 0, ErrNilMap
	}
	pps, ok := npm[name]
	if !ok {
		// Return an error the caller can filer out as this happens only for egress policy
		// and it is likely the destination POD with the port name is simply not scheduled yet.
		return 0, ErrUnknownNamedPort
	}
	// Find if there is a single port that has no proto conflict and no zero port value
	port := uint16(0)
	err := ErrUnknownNamedPort
	for pp := range pps {
		if pp.Proto != 0 && proto != pp.Proto {
			err = ErrIncompatibleProtocol
			continue // conflicting proto
		}
		if pp.Port == 0 {
			err = ErrNamedPortIsZero
			continue // zero port
		}
		if port != 0 && pp.Port != port {
			return 0, ErrDuplicateNamedPorts
		}
		port = pp.Port
	}
	if port == 0 {
		return 0, err
	}
	return port, nil
}
