// Copyright (c) 2014 Dataence, LLC. All rights reserved.
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

package sequence

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/surge/porter2"
)

var (
	config struct {
		fieldIDs   map[string]FieldType
		fieldNames []string
		fieldTypes []TokenType
	}

	keymaps struct {
		keywords map[string]FieldType
		prekeys  map[string][]FieldType
	}

	FieldTypesCount int
	TokenTypesCount = int(token__END__) + 1
	allTypesCount   int
)

func ReadConfig(file string) error {
	if _, err := toml.DecodeFile(file, &configInfo); err != nil {
		return err
	}

	config.fieldIDs = make(map[string]FieldType, 30)
	config.fieldNames = config.fieldNames[:0]
	config.fieldTypes = config.fieldTypes[:0]

	keymaps.keywords = make(map[string]FieldType, 30)
	keymaps.prekeys = make(map[string][]FieldType, 30)

	var ftype FieldType = 0
	config.fieldIDs["funknown"] = ftype
	config.fieldNames = append(config.fieldNames, "funknown")
	config.fieldTypes = append(config.fieldTypes, TokenUnknown)
	ftype++

	for _, f := range configInfo.Parser.Fields {
		fs := strings.Split(f, ":")
		if len(fs) != 2 || fs[1] == "" {
			return fmt.Errorf("Error parsing field %q: missing token type", f)
		}

		// field type name, token type
		tt := name2TokenType(fs[1])
		if tt < TokenLiteral || tt > TokenString {
			return fmt.Errorf("Error parsing field %q: invalid token type", f)
		}

		config.fieldIDs[fs[0]] = ftype
		config.fieldNames = append(config.fieldNames, fs[0])
		config.fieldTypes = append(config.fieldTypes, tt)
		ftype++
	}

	for f, t := range config.fieldIDs {
		predefineAnalyzerFields(f, t)
	}

	for w, list := range configInfo.Analyzer.Keywords {
		if f, ok := config.fieldIDs[w]; ok {
			for _, kw := range list {
				pw := porter2.Stem(kw)
				keymaps.keywords[pw] = f
			}
		}
	}

	for w, m := range configInfo.Analyzer.Prekeys {
		for _, fw := range m {
			if f, ok := config.fieldIDs[fw]; ok {
				keymaps.prekeys[w] = append(keymaps.prekeys[w], f)
			}
		}
	}

	FieldTypesCount = len(config.fieldNames)
	allTypesCount = TokenTypesCount + FieldTypesCount

	return nil
}

var configInfo struct {
	Parser   parserInfo
	Analyzer analyzerInfo
}

type parserInfo struct {
	Fields []string
	ids    map[string]int
}

type analyzerInfo struct {
	Prekeys  map[string][]string
	Keywords map[string][]string
}

func predefineAnalyzerFields(f string, t FieldType) {
	switch f {
	case "msgid":
		FieldMsgId = t
	case "msgtime":
		FieldMsgTime = t
	case "severity":
		FieldSeverity = t
	case "priority":
		FieldPriority = t
	case "apphost":
		FieldAppHost = t
	case "appip":
		FieldAppIP = t
	case "appvendor":
		FieldAppVendor = t
	case "appname":
		FieldAppName = t
	case "srcdomain":
		FieldSrcDomain = t
	case "srczone":
		FieldSrcZone = t
	case "srchost":
		FieldSrcHost = t
	case "srcip":
		FieldSrcIP = t
	case "srcipnat":
		FieldSrcIPNAT = t
	case "srcport":
		FieldSrcPort = t
	case "srcportnat":
		FieldSrcPortNAT = t
	case "srcmac":
		FieldSrcMac = t
	case "srcuser":
		FieldSrcUser = t
	case "srcuid":
		FieldSrcUid = t
	case "srcgroup":
		FieldSrcGroup = t
	case "srcgid":
		FieldSrcGid = t
	case "srcemail":
		FieldSrcEmail = t
	case "dstdomain":
		FieldDstDomain = t
	case "dstzone":
		FieldDstZone = t
	case "dsthost":
		FieldDstHost = t
	case "dstip":
		FieldDstIP = t
	case "dstipnat":
		FieldDstIPNAT = t
	case "dstport":
		FieldDstPort = t
	case "dstportnat":
		FieldDstPortNAT = t
	case "dstmac":
		FieldDstMac = t
	case "dstuser":
		FieldDstUser = t
	case "dstuid":
		FieldDstUid = t
	case "dstgroup":
		FieldDstGroup = t
	case "dstgid":
		FieldDstGid = t
	case "dstemail":
		FieldDstEmail = t
	case "protocol":
		FieldProtocol = t
	case "iniface":
		FieldInIface = t
	case "outiface":
		FieldOutIface = t
	case "policyid":
		FieldPolicyID = t
	case "sessionid":
		FieldSessionID = t
	case "object":
		FieldObject = t
	case "action":
		FieldAction = t
	case "command":
		FieldCommand = t
	case "method":
		FieldMethod = t
	case "status":
		FieldStatus = t
	case "reason":
		FieldReason = t
	case "bytesrecv":
		FieldBytesRecv = t
	case "bytessent":
		FieldBytesSent = t
	case "pktsrecv":
		FieldPktsRecv = t
	case "pktssent":
		FieldPktsSent = t
	case "duration":
		FieldDuration = t
	}
}

var (
	FieldUnknown    FieldType = 0
	FieldMsgId      FieldType // The message identifier
	FieldMsgTime    FieldType // The timestamp that’s part of the log message
	FieldSeverity   FieldType // The severity of the event, e.g., Emergency, …
	FieldPriority   FieldType // The pirority of the event
	FieldAppHost    FieldType // The hostname of the host where the log message is generated
	FieldAppIP      FieldType // The IP address of the host where the application that generated the log message is running on.
	FieldAppVendor  FieldType // The type of application that generated the log message, e.g., Cisco, ISS
	FieldAppName    FieldType // The name of the application that generated the log message, e.g., asa, snort, sshd
	FieldSrcDomain  FieldType // The domain name of the initiator of the event, usually a Windows domain
	FieldSrcZone    FieldType // The originating zone
	FieldSrcHost    FieldType // The hostname of the originator of the event or connection.
	FieldSrcIP      FieldType // The IPv4 address of the originator of the event or connection.
	FieldSrcIPNAT   FieldType // The natted (network address translation) IP of the originator of the event or connection.
	FieldSrcPort    FieldType // The port number of the originating connection.
	FieldSrcPortNAT FieldType // The natted port number of the originating connection.
	FieldSrcMac     FieldType // The mac address of the host that originated the connection.
	FieldSrcUser    FieldType // The user that originated the session.
	FieldSrcUid     FieldType // The user id that originated the session.
	FieldSrcGroup   FieldType // The group that originated the session.
	FieldSrcGid     FieldType // The group id that originated the session.
	FieldSrcEmail   FieldType // The originating email address
	FieldDstDomain  FieldType // The domain name of the destination of the event, usually a Windows domain
	FieldDstZone    FieldType // The destination zone
	FieldDstHost    FieldType // The hostname of the destination of the event or connection.
	FieldDstIP      FieldType // The IPv4 address of the destination of the event or connection.
	FieldDstIPNAT   FieldType // The natted (network address translation) IP of the destination of the event or connection.
	FieldDstPort    FieldType // The destination port number of the connection.
	FieldDstPortNAT FieldType // The natted destination port number of the connection.
	FieldDstMac     FieldType // The mac address of the destination host.
	FieldDstUser    FieldType // The user at the destination.
	FieldDstUid     FieldType // The user id that originated the session.
	FieldDstGroup   FieldType // The group that originated the session.
	FieldDstGid     FieldType // The group id that originated the session.
	FieldDstEmail   FieldType // The destination email address
	FieldProtocol   FieldType // The protocol, such as TCP, UDP, ICMP, of the connection
	FieldInIface    FieldType // The incoming FieldTypeerface
	FieldOutIface   FieldType // The outgoing FieldTypeerface
	FieldPolicyID   FieldType // The policy ID
	FieldSessionID  FieldType // The session or process ID
	FieldObject     FieldType // The object affected.
	FieldAction     FieldType // The action taken
	FieldCommand    FieldType // The command executed
	FieldMethod     FieldType // The method in which the action was taken, for example, public key or password for ssh
	FieldStatus     FieldType // The status of the action taken
	FieldReason     FieldType // The reason for the action taken or the status returned
	FieldBytesRecv  FieldType // The number of bytes received
	FieldBytesSent  FieldType // The number of bytes sent
	FieldPktsRecv   FieldType // The number of packets received
	FieldPktsSent   FieldType // The number of packets sent
	FieldDuration   FieldType // The duration of the session
)
