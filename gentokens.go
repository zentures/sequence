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

// +build ignore

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

var (
	tokens = []struct {
		key     string
		name    string
		comment string
	}{
		{"%tunknown%", "TokenUnknown", "Unknown token"},
		{"%literal%", "TokenLiteral", "Token is a fixed literal"},
		{"%time%", "TokenTime", "Token is a timestamp, in the format listed in TimeFormats"},
		{"%ipv4%", "TokenIPv4", "Token is an IPv4 address, in the form of a.b.c.d"},
		{"%ipv6%", "TokenIPv6", "Token is an IPv6 address, not currently supported"},
		{"%integer%", "TokenInteger", "Token is an integer number"},
		{"%float%", "TokenFloat", "Token is a floating point number"},
		{"%url%", "TokenURL", "Token is an URL, in the form of http://... or https://..."},
		{"%mac%", "TokenMac", "Token is a mac address"},
		{"%string%", "TokenString", "Token is a string that reprensents multiple possible values"},
		{"token__END__", "token__END__", "All field types must be inserted before this one"},
		{"token__host__", "token__host__", "Token is a host name"},
		{"token__email__", "token__email__", "Token is an email address"},
	}

	fields = []struct {
		key     string
		name    string
		token   string
		comment string
	}{
		{"%funknown%", "FieldUnknown", "TokenString", "Unknown field type"},
		{"%msgid%", "FieldMsgId", "TokenString", "The message identifier"},
		{"%msgtime%", "FieldMsgTime", "TokenTime", "The timestamp that’s part of the log message"},
		{"%severity%", "FieldSeverity", "TokenInteger", "The severity of the event, e.g., Emergency, …"},
		{"%priority%", "FieldPriority", "TokenInteger", "The pirority of the event"},
		{"%apphost%", "FieldAppHost", "TokenString", "The hostname of the host where the log message is generated"},
		{"%appipv4%", "FieldAppIPv4", "TokenIPv4", "The IP address of the host where the application that generated the log message is running on."},
		{"%appvendor%", "FieldAppVendor", "TokenString", "The type of application that generated the log message, e.g., Cisco, ISS"},
		{"%appname%", "FieldAppName", "TokenString", "The name of the application that generated the log message, e.g., asa, snort, sshd"},
		{"%srcdomain%", "FieldSrcDomain", "TokenString", "The domain name of the initiator of the event, usually a Windows domain"},
		{"%srczone%", "FieldSrcZone", "TokenString", "The originating zone"},
		{"%srchost%", "FieldSrcHost", "TokenString", "The hostname of the originator of the event or connection."},
		{"%srcipv4%", "FieldSrcIPv4", "TokenIPv4", "The IPv4 address of the originator of the event or connection."},
		{"%srcipv4nat%", "FieldSrcIPv4NAT", "TokenIPv4", "The natted (network address translation) IP of the originator of the event or connection."},
		{"%srcipv6%", "FieldSrcIPv6", "TokenIPv6", "The IPv6 address of the originator of the event or connection."},
		{"%srcport%", "FieldSrcPort", "TokenInteger", "The port number of the originating connection."},
		{"%srcportnat%", "FieldSrcPortNAT", "TokenInteger", "The natted port number of the originating connection."},
		{"%srcmac%", "FieldSrcMac", "TokenMac", "The mac address of the host that originated the connection."},
		{"%srcuser%", "FieldSrcUser", "TokenString", "The user that originated the session."},
		{"%srcuid%", "FieldSrcUid", "TokenInteger", "The user id that originated the session."},
		{"%srcgroup%", "FieldSrcGroup", "TokenString", "The group that originated the session."},
		{"%srcgid%", "FieldSrcGid", "TokenInteger", "The group id that originated the session."},
		{"%srcemail%", "FieldSrcEmail", "TokenString", "The originating email address"},
		{"%dstdomain%", "FieldDstDomain", "TokenString", "The domain name of the destination of the event, usually a Windows domain"},
		{"%dstzone%", "FieldDstZone", "TokenString", "The destination zone"},
		{"%dsthost%", "FieldDstHost", "TokenString", "The hostname of the destination of the event or connection."},
		{"%dstipv4%", "FieldDstIPv4", "TokenIPv4", "The IPv4 address of the destination of the event or connection."},
		{"%dstipv4nat%", "FieldDstIPv4NAT", "TokenIPv4", "The natted (network address translation) IP of the destination of the event or connection."},
		{"%dstipv6%", "FieldDstIPv6", "TokenIPv6", "The IPv6 address of the destination of the event or connection."},
		{"%dstport%", "FieldDstPort", "TokenInteger", "The destination port number of the connection."},
		{"%dstportnat%", "FieldDstPortNAT", "TokenInteger", "The natted destination port number of the connection."},
		{"%dstmac%", "FieldDstMac", "TokenMac", "The mac address of the destination host."},
		{"%dstuser%", "FieldDstUser", "TokenString", "The user at the destination."},
		{"%dstuid%", "FieldDstUid", "TokenInteger", "The user id that originated the session."},
		{"%dstgroup%", "FieldDstGroup", "TokenString", "The group that originated the session."},
		{"%dstgid%", "FieldDstGid", "TokenInteger", "The group id that originated the session."},
		{"%dstemail%", "FieldDstEmail", "TokenString", "The destination email address"},
		{"%protocol%", "FieldProtocol", "TokenString", "The protocol, such as TCP, UDP, ICMP, of the connection"},
		{"%iniface%", "FieldInIface", "TokenString", "The incoming interface"},
		{"%outiface%", "FieldOutIface", "TokenString", "The outgoing interface"},
		{"%policyid%", "FieldPolicyID", "TokenInteger", "The policy ID"},
		{"%sessionid%", "FieldSessionID", "TokenInteger", "The session or process ID"},
		{"%object%", "FieldObject", "TokenString", "The object affected."},
		{"%action%", "FieldAction", "TokenString", "The action taken"},
		{"%command%", "FieldCommand", "TokenString", "The command executed"},
		{"%method%", "FieldMethod", "TokenString", "The method in which the action was taken, for example, public key or password for ssh"},
		{"%status%", "FieldStatus", "TokenString", "The status of the action taken"},
		{"%reason%", "FieldReason", "TokenString", "The reason for the action taken or the status returned"},
		{"%bytesrecv%", "FieldBytesRecv", "TokenInteger", "The number of bytes received"},
		{"%bytessent%", "FieldBytesSent", "TokenInteger", "The number of bytes sent"},
		{"%pktsrecv%", "FieldPktsRecv", "TokenInteger", "The number of packets received"},
		{"%pktssent%", "FieldPktsSent", "TokenInteger", "The number of packets sent"},
		{"%duration%", "FieldDuration", "TokenString", "The duration of the session"},
		{"field__END__", "field__END__", "TokenString", "All field types must be inserted before this one"},
	}
)

func generate(file *os.File) {
	fmt.Fprintf(file, `// Copyright (c) 2014 Dataence, LLC. All rights reserved.
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

// This file is automatically generated by 'gentokens.go' using 'go generate',
// and MUST not be modified. The 'go generate' line is in sequence.go.
// This file is generated on %s.

package sequence

import "fmt"

// Token is a piece of information extracted from a log message. The Scanner will do
// its best to determine the TokenType which could be a time stamp, IPv4 or IPv6
// address, a URL, a mac address, an integer or a floating point number. In addition,
// if the Scanner finds a token that's surrounded by %%, e.g., %%srcuser%%, it will
// try to determine the correct field type the token represents.
type Token struct {
	Type  TokenType // Type is the type of token the Value represents.
	Field FieldType // Field determines which field the Value should be.
	Value string    // Value is the extracted string from the log message.

	isValue bool // Is this token a key in k=v pair
	isKey   bool // Is this token a value in k=v pair
}

func (this Token) String() string {
	return fmt.Sprintf("{ Field=%%q, Type=%%q, Value=%%q, isKey=%%t, isValue=%%t }", this.Field, this.Type, this.Value, this.isKey, this.isValue)
}

type (
	// FieldType is the semantic representation of a token.
	FieldType int

	// Tokentype is the lexical representation of a token.
	TokenType int
)

const (
	metaMore = '+'
	metaRest = '-'
)

const (
	partialMatchWeight = 1
	fullMatchWeight    = 2

	FieldTypesCount    = int(field__END__) + 1
	TokenTypesCount    = int(token__END__) + 1
	allTypesCount      = FieldTypesCount + TokenTypesCount
)

const (
`, time.Now())

	for i, t := range tokens {
		if i == 0 {
			fmt.Fprintf(file, "\t%s TokenType = iota // %s\n", t.name, t.comment)
		} else {
			fmt.Fprintf(file, "\t%s // %s\n", t.name, t.comment)
		}
	}

	fmt.Fprintln(file, ")\n\nconst (")

	for i, f := range fields {
		if i == 0 {
			fmt.Fprintf(file, "\t%s FieldType = iota // %s\n", f.name, f.comment)
		} else {
			fmt.Fprintf(file, "\t%s // %s\n", f.name, f.comment)
		}
	}

	fmt.Fprintln(file, `)

var (
	tokens = []struct {
		label string
	}{`)

	for _, t := range tokens {
		fmt.Fprintf(file, "\t\t{ %q },\n", t.key)
	}

	fmt.Fprintln(file, `	}

	fields = []struct {
		label string
		ttype TokenType
	}{`)

	for _, f := range fields {
		fmt.Fprintf(file, "\t\t{ %q, %s },\n", f.key, f.token)
	}

	fmt.Fprintln(file, `	}
)

func (this TokenType) String() string {
	return tokens[this].label
}

func (this FieldType) String() string {
	return fields[this].label
}

func name2TokenType(s string) TokenType {
	switch s {`)

	for _, n := range tokens {
		fmt.Fprintf(file, "\tcase %q:\n\t\treturn %s\n", n.key, n.name)
	}

	fmt.Fprintln(file, `	}

	return TokenUnknown
}

func name2FieldType(s string) FieldType {
	switch s {`)

	for _, n := range fields {
		fmt.Fprintf(file, "\tcase %q:\n\t\treturn %s\n", n.key, n.name)
	}

	fmt.Fprintln(file, `	}

	return FieldUnknown
}

func (this FieldType) TokenType() TokenType {
	return fields[this].ttype
}`)
}

func outputFile(fname string) *os.File {
	var (
		ofile *os.File = os.Stdin
		err   error
	)

	if fname != "" {
		// Open output file
		ofile, err = os.OpenFile(fname, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
	}

	return ofile
}

func main() {
	flag.Parse()

	f := outputFile(flag.Arg(0))
	defer f.Close()

	//buildfsms()
	generate(f)
}
