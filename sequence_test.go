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
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	seqAnalyzeTests = []struct {
		msg string
		seq Sequence
	}{
		{
			"Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2", Sequence{
				Token{Field: FieldMsgTime, Type: TokenTime, Value: "Jan 12 06:49:42", isKey: false, isValue: false},
				Token{Field: FieldAppHost, Type: TokenString, Value: "irc", isKey: false, isValue: false},
				Token{Field: FieldAppName, Type: TokenString, Value: "sshd", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldSessionID, Type: TokenInteger, Value: "7034", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldStatus, Type: TokenString, Value: "failed", isKey: false, isValue: false},
				Token{Field: FieldMethod, Type: TokenString, Value: "password", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "for", isKey: true, isValue: false},
				Token{Field: FieldSrcUser, Type: TokenString, Value: "root", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "from", isKey: true, isValue: false},
				Token{Field: FieldSrcIPv4, Type: TokenIPv4, Value: "218.161.81.238", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "port", isKey: true, isValue: false},
				Token{Field: FieldSrcPort, Type: TokenInteger, Value: "4228", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "ssh2", isKey: false, isValue: false},
			},
		},

		{
			"Jan 12 06:49:42 irc sshd[7034]: Accepted password for root from 218.161.81.238 port 4228 ssh2", Sequence{
				Token{Field: FieldMsgTime, Type: TokenTime, Value: "Jan 12 06:49:42", isKey: false, isValue: false},
				Token{Field: FieldAppHost, Type: TokenString, Value: "irc", isKey: false, isValue: false},
				Token{Field: FieldAppName, Type: TokenString, Value: "sshd", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldSessionID, Type: TokenInteger, Value: "7034", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldStatus, Type: TokenString, Value: "accepted", isKey: false, isValue: false},
				Token{Field: FieldMethod, Type: TokenString, Value: "password", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "for", isKey: true, isValue: false},
				Token{Field: FieldSrcUser, Type: TokenString, Value: "root", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "from", isKey: true, isValue: false},
				Token{Field: FieldSrcIPv4, Type: TokenIPv4, Value: "218.161.81.238", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "port", isKey: true, isValue: false},
				Token{Field: FieldSrcPort, Type: TokenInteger, Value: "4228", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "ssh2", isKey: false, isValue: false},
			},
		},

		{
			"Jan 12 14:44:48 jlz sshd[11084]: Accepted publickey for jlz from 76.21.0.16 port 36609 ssh2", Sequence{
				Token{Field: FieldMsgTime, Type: TokenTime, Value: "Jan 12 14:44:48", isKey: false, isValue: false},
				Token{Field: FieldAppHost, Type: TokenString, Value: "jlz", isKey: false, isValue: false},
				Token{Field: FieldAppName, Type: TokenString, Value: "sshd", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldSessionID, Type: TokenInteger, Value: "11084", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldStatus, Type: TokenString, Value: "accepted", isKey: false, isValue: false},
				Token{Field: FieldMethod, Type: TokenString, Value: "publickey", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "for", isKey: true, isValue: false},
				Token{Field: FieldSrcUser, Type: TokenString, Value: "jlz", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "from", isKey: true, isValue: false},
				Token{Field: FieldSrcIPv4, Type: TokenIPv4, Value: "76.21.0.16", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "port", isKey: true, isValue: false},
				Token{Field: FieldSrcPort, Type: TokenInteger, Value: "36609", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "ssh2", isKey: false, isValue: false},
			},
		},
		{
			"209.36.88.3 - - [03/may/2004:01:19:07 +0000] \"get http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectrange&dr=0month&so=relevance&st=nw&ss=afr&sf=article&rc=00&clspage=0&docid=fin0000000r0jl000d00 http/1.0\" 200 27981", Sequence{
				Token{Field: FieldSrcIPv4, Type: TokenIPv4, Value: "209.36.88.3", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldMsgTime, Type: TokenTime, Value: "03/may/2004:01:19:07 +0000", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldAction, Type: TokenString, Value: "get", isKey: false, isValue: false},
				Token{Field: FieldObject, Type: TokenString, Value: "http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectrange&dr=0month&so=relevance&st=nw&ss=afr&sf=article&rc=00&clspage=0&docid=fin0000000r0jl000d00", isKey: false, isValue: false},
				Token{Field: FieldProtocol, Type: TokenString, Value: "http/1.0", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "200", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "27981", isKey: false, isValue: false},
			},
		},

		{
			"2012-04-05 17:54:47     local4.info     172.23.0.1      %asa-6-302015: built outbound udp connection 1315679 for outside:193.0.14.129/53 (193.0.14.129/53) to inside:172.23.0.10/64048 (10.32.0.1/52130)", Sequence{
				Token{Field: FieldMsgTime, Type: TokenTime, Value: "2012-04-05 17:54:47", isKey: false, isValue: false},
				Token{Field: FieldSrcHost, Type: TokenString, Value: "local4.info", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "172.23.0.1", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "%asa-6-302015", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldAction, Type: TokenString, Value: "built", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "outbound", isKey: false, isValue: false},
				Token{Field: FieldProtocol, Type: TokenString, Value: "udp", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "connection", isKey: true, isValue: false},
				Token{Field: FieldSessionID, Type: TokenInteger, Value: "1315679", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "for", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "outside", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldSrcIPv4, Type: TokenIPv4, Value: "193.0.14.129", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "/", isKey: false, isValue: false},
				Token{Field: FieldSrcPort, Type: TokenInteger, Value: "53", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "(", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "193.0.14.129", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "/", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "53", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ")", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "to", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "inside", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldDstIPv4, Type: TokenIPv4, Value: "172.23.0.10", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "/", isKey: false, isValue: false},
				Token{Field: FieldDstPort, Type: TokenInteger, Value: "64048", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "(", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "10.32.0.1", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "/", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "52130", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ")", isKey: false, isValue: false},
			},
		},

		{
			"Jan 15 05:14:39 irc sshd[8134]: Address 123.30.182.178 maps to static.vdc.vn, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!", Sequence{
				Token{Field: FieldMsgTime, Type: TokenTime, Value: "Jan 15 05:14:39", isKey: false, isValue: false},
				Token{Field: FieldAppHost, Type: TokenString, Value: "irc", isKey: false, isValue: false},
				Token{Field: FieldAppName, Type: TokenString, Value: "sshd", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldSessionID, Type: TokenInteger, Value: "8134", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "address", isKey: false, isValue: false},
				Token{Field: FieldSrcIPv4, Type: TokenIPv4, Value: "123.30.182.178", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "maps", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "to", isKey: true, isValue: false},
				Token{Field: FieldDstHost, Type: TokenString, Value: "static.vdc.vn", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ",", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "but", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "this", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "does", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "not", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "map", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "back", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "to", isKey: true, isValue: false},
				Token{Field: FieldDstUser, Type: TokenString, Value: "the", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "address", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "possible", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "break-in", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "attempt", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "!", isKey: false, isValue: false},
			},
		},

		{
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80", Sequence{
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "id", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenString, Value: "firewall", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "time", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldMsgTime, Type: TokenTime, Value: "2005-03-18 14:01:46", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "fw", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenString, Value: "TOPSEC", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "priv", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "6", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "recorder", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenString, Value: "kernel", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "type", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenString, Value: "conn", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "policy", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "414", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "proto", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldProtocol, Type: TokenString, Value: "TCP", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "rule", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenString, Value: "accept", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "src", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldSrcIPv4, Type: TokenIPv4, Value: "61.167.71.244", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "sport", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldSrcPort, Type: TokenInteger, Value: "35223", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "dst", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldDstIPv4, Type: TokenIPv4, Value: "210.82.119.211", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "dport", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldDstPort, Type: TokenInteger, Value: "25", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "duration", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "27", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "inpkt", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "37", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "outpkt", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "39", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "sent", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "1770", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "rcvd", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "20926", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "smac", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldSrcMac, Type: TokenMac, Value: "00:04:c1:8b:d8:82", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "dmac", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldDstMac, Type: TokenMac, Value: "00:0b:5f:b2:1d:80", isKey: false, isValue: true},
			},
		},
	}
)

func TestAnalyzeSequence(t *testing.T) {
	seq := make(Sequence, 0, 20)

	for _, tc := range seqAnalyzeTests {
		seq = seq[:0]
		seq, err := DefaultScanner.Tokenize(tc.msg, seq)
		require.NoError(t, err)
		seq = analyzeSequence(seq)
		//glog.Debugln(seq.PrintTokens())
		for i, tok := range seq {
			if tok != tc.seq[i] {
				require.FailNow(t, tok.String()+" != "+tc.seq[i].String()+"\n"+tc.msg)
			}
		}
		require.Equal(t, tc.seq, seq, tc.msg)
	}
}
