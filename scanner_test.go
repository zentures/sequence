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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScannerRequestMethods(t *testing.T) {
	for _, m := range methodtests {
		l := matchRequestMethods(m.data + " ")
		require.Equal(t, m.l, l, m.data)

		l = matchRequestMethods(strings.ToLower(m.data) + " ")
		require.Equal(t, m.l, l, m.data)
	}
}

func TestMessageScanTokens(t *testing.T) {
	msg := &Message{}

	for _, tc := range tokentests {
		var (
			stop bool
			l    int
		)

		msg.reset()

		for i, r := range tc.data {
			stop = msg.tokenStep(i, r)
			if stop {
				//glog.Debugf("i=%d, r=%c, stop=%t", i, r, stop)
				if l == 0 {
					l = 1
				}
				break
			}
			l++
		}

		require.Equal(t, tc.result, tc.data[:l], tc.data)
		require.Equal(t, tc.ttype, msg.state.tokenType, tc.data)
	}
}

func TestMessageScanHexString(t *testing.T) {
	msg := &Message{}

	for _, tc := range hextests {
		var valid, stop bool

		msg.resetHexStates()

		for i, r := range tc.data {
			valid, stop = msg.hexStep(i, r)
			if stop {
				break
			}
		}
		valid = valid && msg.state.hexSuccColonsSeries < 2 && msg.state.hexMaxSuccColons < 3
		require.Equal(t, tc.valid, valid, tc.data)
	}
}

func TestScannerSignature(t *testing.T) {
	scanner := NewScanner()

	for _, tc := range sigtests {
		seq, err := scanner.Scan(tc.data)
		require.NoError(t, err, tc.data)
		require.Equal(t, tc.sig, seq.Signature(), tc.data+"\n"+seq.PrintTokens())
	}
}

func TestScannerScan(t *testing.T) {
	runTestCases(t, scantests)
}

func BenchmarkScannerScanGeneral(b *testing.B) {
	benchmarkScanner(b, scantests[0].data, "general")
}

func BenchmarkScannerScanJson(b *testing.B) {
	benchmarkScanner(b, scantests[len(scantests)-1].data, "json")
}

func BenchmarkScannerScanJsonGeneral(b *testing.B) {
	benchmarkScanner(b, scantests[len(scantests)-1].data, "general")
}

func benchmarkScanner(b *testing.B, data string, stype string) {
	scanner := NewScanner()
	l := int64(len(data))

	var benchFunc func(string) (Sequence, error)

	switch stype {
	case "json":
		benchFunc = scanner.ScanJson

	default:
		benchFunc = scanner.Scan
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.SetBytes(l)
		benchFunc(data)
	}
}

func runTestCases(t *testing.T, tests []testCase) {
	scanner := NewScanner()

	for _, tc := range tests {
		var (
			seq Sequence
			err error
		)

		switch tc.format {
		case "json":
			seq, err = scanner.ScanJson(tc.data)

		default:
			seq, err = scanner.Scan(tc.data)
		}

		require.NoError(t, err, tc.data)

		if len(tc.seq) == 0 {
			require.FailNow(t, seq.PrintTokens())
		} else {
			for i, tok := range seq {
				require.Equal(t, tc.seq[i], tok, tc.data)
			}
		}
	}
}

type testCase struct {
	format string
	data   string
	seq    Sequence
}

var (
	methodtests = []struct {
		data string
		l    int
	}{
		{"GET", 3},
		{"PUT", 3},
		{"POST", 4},
		{"DELETE", 6},
		{"CONNECT", 7},
		{"OPTIONS", 7},
		{"TRACE", 5},
		{"PATCH", 5},
		{"PROPFIND", 8},
		{"PROPPATCH", 9},
		{"MKCOL", 5},
		{"COPY", 4},
		{"MOVE", 4},
		{"LOCK", 4},
		{"UNLOCK", 6},
		{"VERSION_CONTROL", 15},
		{"CHECKOUT", 8},
		{"UNCHECKOUT", 10},
		{"CHECKIN", 7},
		{"UPDATE", 6},
		{"LABEL", 5},
		{"REPORT", 6},
		{"MKWORKSPACE", 11},
		{"MKACTIVITY", 10},
		{"BASELINE_CONTROL", 16},
		{"MERGE", 5},
		{"INVALID", 7},
	}

	hextests = []struct {
		data  string
		valid bool
	}{
		{"f0::1", true},
		{"f0f0::1", true},
		{"1:2:3:4:5:6:1:2", true},
		{"0:0:0:0:0:0:0:0", true},
		{"1:2:3:4:5::7:8", true},
		{"f0f0::f:1", true},
		{"f0f0:f::1", true},
		{"f0::1", true},
		{"::2:3:4", true},
		{"0:0:0:0:0:0:0:5", true},
		{"::5", true},
		{"::", true},
		{"ABC:567:0:0:8888:9999:1111:0", true},
		{"ABC:567::8888:9999:1111:0", true},
		{"ABC:567::8888:9999:1111:0 ", true}, // space at the end
		{"ABC::567::891::00", false},
		{":::00", false},
		{"00:04:c1:8b:d8:82", true},
		{"de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56", true},
		{"00:0b:5f:b2:1d:80", true},
		{"00:04:c1:8b:d8:82", true},
		{"00:04:c1:8b:d8:82 ", true}, // space at end
		{"0:09:23 ", true},
		{"g:09:23 ", false},
		{"dead:beef:1234:5678:223:32ff:feb1:2e50", true},
		{"12345:32432:3232", false},
	}

	tokentests = []struct {
		data   string
		result string
		ttype  TokenType
	}{
		{"http://WSsamples", "http://WSsamples", TokenURI},
		{"123.456.78.23", "123.456.78.23", TokenIPv4},
		{"egreetings@vishwak.com", "egreetings@vishwak.com", TokenLiteral},
		{"(smtp:5.5.5.5)", "(", TokenLiteral},
		{"smtp:5.5.5.5)", "smtp", TokenLiteral},
		{":5.5.5.5)", ":", TokenLiteral},
		{"5.5.5.5)", "5.5.5.5", TokenIPv4},
		{"\"aws-cli/1.3.2 Python/2.7.5 Windows/7\"", "\"", TokenLiteral},
		{"aws-cli/1.3.2 Python/2.7.5 Windows/7\"", "aws-cli/1.3.2", TokenLiteral},
		{"\"", "\"", TokenLiteral},
		{"arn:aws:iam::123456789012:user/Alice", "arn", TokenLiteral},
		{":aws:iam::123456789012:user/Alice", ":", TokenLiteral},
		{"aws:iam::123456789012:user/Alice", "aws", TokenLiteral},
		{":iam::123456789012:user/Alice", ":", TokenLiteral},
		{"iam::123456789012:user/Alice", "iam", TokenLiteral},
		{"::123456789012:user/Alice", ":", TokenLiteral},
		{":123456789012:user/Alice", ":", TokenLiteral},
		{"123456789012:user/Alice", "123456789012", TokenInteger},
		{":user/Alice", ":", TokenLiteral},
		{"user/Alice", "user/Alice", TokenLiteral},
		{"192.168.20.20/33", "192.168.20.20", TokenIPv4},
		{"192.168 3", "192.168", TokenFloat},
	}

	sigtests = []struct {
		data, sig string
	}{
		{
			"2.0.0",
			"",
		},
		{
			"jan 12 06:49:41 irc sshd[7034]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=218-161-81-238.hinet-ip.hinet.net  user=root",
			"%time%[%integer%]:(:):;==%integer%=%integer%====",
		},
		{
			"jan 12 06:49:42 irc sshd[7034]: failed password for root from 218.161.81.238 port 4228 ssh2",
			"%time%[%integer%]:%ipv4%%integer%",
		},
		{
			"9.26.157.45 - - [16/jan/2003:21:22:59 -0500] \"get /wssamples/ http/1.1\" 200 1576",
			"%ipv4%--[%time%]\"\"%integer%%integer%",
		},
		{
			"209.36.88.3 - - [03/may/2004:01:19:07 +0000] \"get http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectrange&dr=0month&so=relevance&st=nw&ss=afr&sf=article&rc=00&clspage=0&docid=fin0000000r0jl000d00 http/1.0\" 200 27981",
			"%ipv4%--[%time%]\"%uri%\"%integer%%integer%",
		},
		{
			"4/5/2012 17:55,172.23.1.101,1101,172.23.0.10,139, generic protocol command decode,3, [1:2100538:17] gpl netbios smb ipc$ unicode share access ,tcp ttl:128 tos:0x0 id:1643 iplen:20 dgmlen:122 df,***ap*** seq: 0xcef93f32  ack: 0xc40c0bb  n: 0xfc9c  tcplen: 20,",
			"%time%,%ipv4%,%integer%,%ipv4%,%integer%,,%integer%,[%integer%:%integer%:%integer%],:%integer%::%integer%:%integer%:%integer%,::n::%integer%,",
		},
		{
			"2012-04-05 17:54:47     local4.info     172.23.0.1      %asa-6-302015: built outbound udp connection 1315679 for outside:193.0.14.129/53 (193.0.14.129/53) to inside:172.23.0.10/64048 (10.32.0.1/52130)",
			"%time%%ipv4%:%integer%:%ipv4%/%integer%(%ipv4%/%integer%):%ipv4%/%integer%(%ipv4%/%integer%)",
		},
		{
			"may  2 19:00:02 dlfssrv sendmail[18980]: taa18980: from user daemon: size is 596, class is 0, priority is 30596, and nrcpts=1, message id is <200305021400.taa18980@dlfssrv.in.ibm.com>, relay=daemon@localhost",
			"%time%[%integer%]:::%integer%,%integer%,%integer%,=%integer%,<>,=",
		},
		{
			"jan 12 06:49:56 irc last message repeated 6 times",
			"%time%%integer%",
		},
		{
			"9.26.157.44 - - [16/jan/2003:21:22:59 -0500] \"get http://wssamples http/1.1\" 301 315",
			"%ipv4%--[%time%]\"%uri%\"%integer%%integer%",
		},
		{
			"2012-04-05 17:51:26     local4.info     172.23.0.1      %asa-6-302016: teardown udp connection 1315632 for inside:172.23.0.2/514 to identity:172.23.0.1/514 duration 0:09:23 bytes 7999",
			"%time%%ipv4%:%integer%:%ipv4%/%integer%:%ipv4%/%integer%%integer%",
		},
		{
			"id=firewall time=\"2005-03-18 14:01:43\" fw=topsec priv=4 recorder=kernel type=conn policy=504 proto=tcp rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82",
			"==\"%time%\"==%integer%===%integer%===%ipv4%=%integer%=%ipv4%=%integer%=%mac%=%mac%",
		},
		{
			"mar 01 09:42:03.875 pffbisvr smtp[2424]: 334 warning: denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30]",
			"%time%[%integer%]:%integer%:''[%ipv4%]",
		},
		{
			"mar 01 09:45:02.596 pffbisvr smtp[2424]: 121 statistics: duration=181.14 user=<egreetings@vishwak.com> id=zduqd sent=1440 rcvd=356 srcif=d45f49a2-b30 src=209.235.210.30/61663 cldst=192.216.179.206/25 svsrc=172.17.74.195/8423 dstif=fd3c875c-064 dst=172.17.74.52/25 op=\"to 1 recips\" arg=<vishwakstg1ojte15fo000033b4@vishwakstg1.msn.vishwak.net> result=\"250 m2004030109385301402 message accepted for delivery\" proto=smtp rule=131 (denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30])",
			"%time%[%integer%]:%integer%:=%float%=<>==%integer%=%integer%==%ipv4%/%integer%=%ipv4%/%integer%=%ipv4%/%integer%==%ipv4%/%integer%=\"\"=<>=\"\"==%integer%(''[%ipv4%])",
		},
	}

	scantests = []testCase{
		{
			"general",
			"Jan 12 06:49:41 irc sshd[7034]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=218-161-81-238.hinet-ip.hinet.net  user=root", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "Jan 12 06:49:41"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "irc"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "sshd"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "7034"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "pam_unix"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "("},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "sshd"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "auth"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ")"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "authentication"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "failure"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ";"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "logname"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "uid"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "0"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "euid"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "0"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "tty"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "ssh"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "ruser"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "rhost"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "218-161-81-238.hinet-ip.hinet.net"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "user"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "root"},
			},
		},

		{
			"general",
			"Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "Jan 12 06:49:42"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "irc"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "sshd"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "7034"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Failed"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "password"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "for"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "root"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "from"},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "218.161.81.238"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "port"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "4228"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "ssh2"},
			},
		},

		//"Jan 13 17:25:59 jlz sshd[19322]: Accepted password for jlz from 108.61.8.124 port 56731 ssh2",
		//"Jan 12 14:44:48 irc sshd[11084]: Accepted publickey for jlz from 76.21.0.16 port 36609 ssh2",
		{
			"general",
			"Jan 12 06:49:56 irc last message repeated 6 times", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "Jan 12 06:49:56"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "irc"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "last"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "message"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "repeated"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "6"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "times"},
			},
		},

		{
			"general",
			`9.26.157.44 - - [16/Jan/2003:21:22:59 -0500] "GET http://WSsamples HTTP/1.1" 301 315`, Sequence{
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "9.26.157.44"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenTime, Field: FieldUnknown, Value: "16/Jan/2003:21:22:59 -0500"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "GET"},
				Token{Type: TokenURI, Field: FieldUnknown, Value: "http://WSsamples"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "HTTP/1.1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "301"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "315"},
			},
		},

		{
			"general",
			`9.26.157.45 - - [16/Jan/2003:21:22:59 -0500] "GET /WSsamples/ HTTP/1.1" 200 1576`, Sequence{
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "9.26.157.45"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenTime, Field: FieldUnknown, Value: "16/Jan/2003:21:22:59 -0500"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "GET"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/WSsamples/"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "HTTP/1.1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "200"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1576"},
			},
		},

		{
			"general",
			`209.36.88.3 - - [03/May/2004:01:19:07 +0000] "GET http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectRange&dr=0month&so=relevance&st=nw&ss=AFR&sf=article&rc=00&clsPage=0&docID=FIN0000000R0JL000D00 HTTP/1.0" 200 27981`, Sequence{
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "209.36.88.3"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenTime, Field: FieldUnknown, Value: "03/May/2004:01:19:07 +0000"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "GET"},
				Token{Type: TokenURI, Field: FieldUnknown, Value: "http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectRange&dr=0month&so=relevance&st=nw&ss=AFR&sf=article&rc=00&clsPage=0&docID=FIN0000000R0JL000D00"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "HTTP/1.0"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "200"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "27981"},
			},
		},

		{
			"general",
			"4/5/2012 17:55,172.23.1.101,1101,172.23.0.10,139, Generic Protocol Command Decode,3, [1:2100538:17] GPL NETBIOS SMB IPC$ unicode share access ,TCP TTL:128 TOS:0x0 ID:1643 IpLen:20 DgmLen:122 DF,***AP*** Seq: 0xCEF93F32  Ack: 0xC40C0BB  n: 0xFC9C  TcpLen: 20,", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "4/5/2012 17:55"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.23.1.101"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1101"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.23.0.10"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "139"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Generic"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Protocol"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Command"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Decode"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "3"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "2100538"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "17"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "GPL"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "NETBIOS"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "SMB"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "IPC$"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "unicode"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "share"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "access"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "TCP"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "TTL"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "128"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "TOS"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "0x0"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "ID"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1643"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "IpLen"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "20"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "DgmLen"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "122"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "DF"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "***AP***"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Seq"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "0xCEF93F32"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Ack"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "0xC40C0BB"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "n"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "0xFC9C"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "TcpLen"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "20"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
			},
		},

		{
			"general",
			"2012-04-05 17:51:26     Local4.Info     172.23.0.1      %ASA-6-302016: Teardown UDP connection 1315632 for inside:172.23.0.2/514 to identity:172.23.0.1/514 duration 0:09:23 bytes 7999", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "2012-04-05 17:51:26"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Local4.Info"},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.23.0.1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "%ASA-6-302016"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Teardown"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "UDP"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "connection"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1315632"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "for"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "inside"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.23.0.2"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "514"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "to"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "identity"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.23.0.1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "514"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "duration"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "0:09:23"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "bytes"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "7999"},
			},
		},

		{
			"general",
			"2012-04-05 17:54:47     Local4.Info     172.23.0.1      %ASA-6-302015: Built outbound UDP connection 1315679 for outside:193.0.14.129/53 (193.0.14.129/53) to inside:172.23.0.10/64048 (10.32.0.1/52130)", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "2012-04-05 17:54:47"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Local4.Info"},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.23.0.1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "%ASA-6-302015"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "Built"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "outbound"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "UDP"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "connection"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1315679"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "for"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "outside"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "193.0.14.129"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "53"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "("},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "193.0.14.129"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "53"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ")"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "to"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "inside"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.23.0.10"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "64048"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "("},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "10.32.0.1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "52130"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ")"},
			},
		},

		{
			"general",
			`id=firewall time="2005-03-18 14:01:43" fw=TOPSEC priv=4 recorder=kernel type=conn policy=504 proto=TCP rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82`, Sequence{
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "id"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "firewall"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "time"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenTime, Field: FieldUnknown, Value: "2005-03-18 14:01:43"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "fw"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "TOPSEC"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "priv"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "4"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "recorder"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "kernel"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "type"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "conn"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "policy"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "504"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "proto"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "TCP"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "rule"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "deny"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "src"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "210.82.121.91"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "sport"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "4958"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "dst"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "61.229.37.85"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "dport"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "23124"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "smac"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenMac, Field: FieldUnknown, Value: "00:0b:5f:b2:1d:80"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "dmac"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenMac, Field: FieldUnknown, Value: "00:04:c1:8b:d8:82"},
			},
		},

		{
			"general",
			"mar 01 09:42:03.875 pffbisvr smtp[2424]: 334 warning: denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30]", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "mar 01 09:42:03.875"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "pffbisvr"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "smtp"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "2424"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "334"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "warning"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "denied"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "access"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "to"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "command"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "'"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "ehlo vishwakstg1.msn.vishwak.net"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "'"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "from"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "209.235.210.30"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
			},
		},

		{
			"general",
			"may  2 19:00:02 dlfssrv sendmail[18980]: taa18980: from user daemon: size is 596, class is 0, priority is 30596, and nrcpts=1, message id is <200305021400.taa18980@dlfssrv.in.ibm.com>, relay=daemon@localhost", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "may  2 19:00:02"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "dlfssrv"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "sendmail"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "18980"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "taa18980"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "from"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "user"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "daemon"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "size"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "is"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "596"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "class"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "is"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "0"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "priority"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "is"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "30596"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "and"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "nrcpts"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "message"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "id"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "is"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "<"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "200305021400.taa18980@dlfssrv.in.ibm.com"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ">"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ","},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "relay"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "daemon@localhost"},
			},
		},

		{
			"general",
			"mar 01 09:45:02.596 pffbisvr smtp[2424]: 121 statistics: duration=181.14 user=<egreetings@vishwak.com> id=zduqd sent=1440 rcvd=356 srcif=d45f49a2-b30 src=209.235.210.30/61663 cldst=192.216.179.206/25 svsrc=172.17.74.195/8423 dstif=fd3c875c-064 dst=172.17.74.52/25 op=\"to 1 recips\" arg=<vishwakstg1ojte15fo000033b4@vishwakstg1.msn.vishwak.net> result=\"250 m2004030109385301402 message accepted for delivery\" proto=smtp rule=131 (denied access to command 'ehlo vishwakstg1.msn.vishwak.net' from [209.235.210.30])", Sequence{
				Token{Type: TokenTime, Field: FieldUnknown, Value: "mar 01 09:45:02.596"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "pffbisvr"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "smtp"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "2424"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "121"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "statistics"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ":"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "duration"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenFloat, Field: FieldUnknown, Value: "181.14"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "user"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "<"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "egreetings@vishwak.com"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ">"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "id"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "zduqd"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "sent"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "1440"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "rcvd"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "356"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "srcif"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "d45f49a2-b30"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "src"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "209.235.210.30"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "61663"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "cldst"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "192.216.179.206"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "25"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "svsrc"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.17.74.195"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "8423"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "dstif"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "fd3c875c-064"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "dst"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "172.17.74.52"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "/"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "25"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "op"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "to 1 recips"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "arg"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "<"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "vishwakstg1ojte15fo000033b4@vishwakstg1.msn.vishwak.net"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ">"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "result"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "250 m2004030109385301402 message accepted for delivery"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "proto"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "smtp"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "rule"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "="},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "131"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "("},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "denied"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "access"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "to"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "command"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "'"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "ehlo vishwakstg1.msn.vishwak.net"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "'"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "from"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "209.235.210.30"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: ")"},
			},
		},

		{
			"general",
			"2015-02-11 11:04:40 H=(amoricanexpress.com) [64.20.195.132]:10246 F=<fxC4480@amoricanexpress.com> rejected RCPT <SCRUBBED@SCRUBBED.com>: Sender verify failed", Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2015-02-11 11:04:40", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "H", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "(", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "amoricanexpress.com", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ")", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "64.20.195.132", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "10246", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "F", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "<", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "fxC4480@amoricanexpress.com", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ">", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "rejected", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "RCPT", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "<", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "SCRUBBED@SCRUBBED.com", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ">", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Sender", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "verify", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "failed", isKey: false, isValue: false},
			},
		},

		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection rate 1/60s for (smtp:5.5.5.5) at Jan 31 21:39:37", Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Jan 31 21:42:59", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "mail", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "postfix/anvil", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "14606", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "statistics", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "max", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "connection", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "rate", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "1/60s", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "for", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "(", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "smtp", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "5.5.5.5", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ")", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "at", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Jan 31 21:39:37", isKey: false, isValue: false},
			},
		},

		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection count 1 for (smtp:5.5.5.5) at Jan 31 21:39:37", Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Jan 31 21:42:59", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "mail", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "postfix/anvil", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "14606", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "statistics", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "max", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "connection", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "count", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "1", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "for", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "(", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "smtp", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "5.5.5.5", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ")", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "at", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Jan 31 21:39:37", isKey: false, isValue: false},
			},
		},

		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max cache size 1 at Jan 31 21:39:37", Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Jan 31 21:42:59", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "mail", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "postfix/anvil", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "14606", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "statistics", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "max", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "cache", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "size", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "1", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "at", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Jan 31 21:39:37", isKey: false, isValue: false},
			},
		},

		// relates to #2
		{
			"general",
			"Feb 06 13:37:00 box sshd[4388]: Accepted publickey for cryptix from dead:beef:1234:5678:223:32ff:feb1:2e50 port 58251 ssh2: RSA de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56", Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Feb 06 13:37:00", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "box", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "sshd", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "4388", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Accepted", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "publickey", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "for", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "cryptix", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "from", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv6, Value: "dead:beef:1234:5678:223:32ff:feb1:2e50", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "port", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "58251", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "ssh2", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "RSA", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56", isKey: false, isValue: false},
			},
		},

		// relates to #6
		{
			"general",
			"2015-01-21 21:41:27 4515 [Note] - '::' resolves to '::';", Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2015-01-21 21:41:27", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "4515", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Note", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "'", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv6, Value: "::", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "'", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "resolves", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "to", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "'", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv6, Value: "::", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "'", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ";", isKey: false, isValue: false},
			},
		},

		// relates to #6,
		{
			"general",
			"2015-01-21 21:41:27 4515 [Note] Server socket created on IP: '::'.", Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2015-01-21 21:41:27", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "4515", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Note", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Server", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "socket", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "created", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "on", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "IP", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "'", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv6, Value: "::", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "'", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ".", isKey: false, isValue: false},
			},
		},

		{
			"general",
			"9.26.157.44 - - [16/Jan/2003:21:22:59 -0500] \"GET http://WSsamples HTTP/1.1\" 301 315", Sequence{
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "9.26.157.44"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenTime, Field: FieldUnknown, Value: "16/Jan/2003:21:22:59 -0500"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "GET"},
				Token{Type: TokenURI, Field: FieldUnknown, Value: "http://WSsamples"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "HTTP/1.1"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "301"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "315"},
			},
		},

		{
			"general",
			"209.36.88.3 - - [03/May/2004:01:19:07 +0000] \"GET http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectRange&dr=0month&so=relevance&st=nw&ss=AFR&sf=article&rc=00&clsPage=0&docID=FIN0000000R0JL000D00 HTTP/1.0\" 200 27981", Sequence{
				Token{Type: TokenIPv4, Field: FieldUnknown, Value: "209.36.88.3"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "-"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "["},
				Token{Type: TokenTime, Field: FieldUnknown, Value: "03/May/2004:01:19:07 +0000"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "]"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "GET"},
				Token{Type: TokenURI, Field: FieldUnknown, Value: "http://npkclzicp.xihudohtd.ngm.au/abramson/eiyscmeqix.ac;jsessionid=b0l0v000u0?sid=00000000&sy=afr&kw=goldman&pb=fin&dt=selectRange&dr=0month&so=relevance&st=nw&ss=AFR&sf=article&rc=00&clsPage=0&docID=FIN0000000R0JL000D00"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "HTTP/1.0"},
				Token{Type: TokenLiteral, Field: FieldUnknown, Value: "\""},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "200"},
				Token{Type: TokenInteger, Field: FieldUnknown, Value: "27981"},
			},
		},

		{
			"general",
			`175.185.9.6 - - [12/Jul/2013:15:56:54 +0000] "GET /organizations/exampleorg/data/firewall/nova_api HTTP/1.1" 200 "0.850" 452 "-" "Chef Client/0.10.2 (ruby-1.8.7-p302; ohai-0.6.4; x86_64-linux; +http://opscode.com)" "127.0.0.1:9460" "200" "0.849" "0.10.2" "version=1.0" "some_node.example.com" "2013-07-12T15:56:40Z" "2jmj7l5rSw0yVb/vlWAYkK/YBwk=" 985`, Sequence{
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "175.185.9.6", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "12/Jul/2013:15:56:54 +0000", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "GET", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "/organizations/exampleorg/data/firewall/nova_api", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "HTTP/1.1", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "200", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenFloat, Value: "0.850", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "452", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Chef Client/0.10.2 (ruby-1.8.7-p302; ohai-0.6.4; x86_64-linux; +http://opscode.com)", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "127.0.0.1:9460", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "200", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenFloat, Value: "0.849", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "0.10.2", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "version=1.0", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "some_node.example.com", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2013-07-12T15:56:40Z", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "2jmj7l5rSw0yVb/vlWAYkK/YBwk=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "985", isKey: false, isValue: false},
			},
		},

		{
			"general",
			`209.36.213.112 - - [03/May/2004:01:00:04 +0000] "GET http://www.toxzyyphvc.com/xray/peterson.asp?ProdID=00000&LastUpdate=00000000&Stocks=00:00000|00:000|00:0000|00:000|00:0000|00:0000|00:0000|00:0000|00:000|00:00000|00:000|00:000|00:000|00:0000|00:0000|00:000|00:000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:00000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000&UpdType=0 HTTP/1.0" 200 281`, Sequence{
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "209.36.213.112", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "-", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "03/May/2004:01:00:04 +0000", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "GET", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenURI, Value: "http://www.toxzyyphvc.com/xray/peterson.asp?ProdID=00000&LastUpdate=00000000&Stocks=00:00000|00:000|00:0000|00:000|00:0000|00:0000|00:0000|00:0000|00:000|00:00000|00:000|00:000|00:000|00:0000|00:0000|00:000|00:000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000|00:00000|00:0000|00:0000|00:0000|00:0000|00:0000|00:0000&UpdType=0", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "HTTP/1.0", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "200", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "281", isKey: false, isValue: false},
			},
		},

		{
			"general",
			`2014-02-15T23:39:43.945958Z my-test-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.000073 0.001048 0.000057 200 200 0 29 "GET http://www.example.com:80/HTTP/1.1"`, Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2014-02-15T23:39:43.945958Z", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "my-test-loadbalancer", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "192.168.131.39", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "2817", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "10.0.0.1", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "80", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenFloat, Value: "0.000073", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenFloat, Value: "0.001048", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenFloat, Value: "0.000057", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "200", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "200", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "0", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "29", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "GET", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenURI, Value: "http://www.example.com:80/HTTP/1.1", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "\"", isKey: false, isValue: false},
			},
		},

		// relates to #3
		{
			"general",
			"Feb 06 15:56:09 higgs sshd[902]: Server listening on 0.0.0.0 port 22.",
			Sequence{
				Token{Field: FieldUnknown, Type: TokenTime, Value: "Feb 06 15:56:09", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "higgs", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "sshd", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "[", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "902", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "]", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ":", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Server", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "listening", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "on", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "0.0.0.0", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "port", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "22", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: ".", isKey: false, isValue: false},
			},
		},

		// {
		// 	"2010-03-12	23:51:20	SEA4	192.0.2.147	connect	2014	OK	bfd8a98bee0840d9b871b7f6ade9908f	rtmp://shqshne4jdp4b6.cloudfront.net/cfx/st​	key=value	http://player.longtailvideo.com/player.swf	http://www.longtailvideo.com/support/jw-player-setup-wizard?example=204	LNX%2010,0,32,18	-	-	-	-", Sequence{},
		// },

		// {
		// 	"Feb  8 23:49:58 mail postfix/pipe[85979]: B9E532E0B: to=<userB@company.office>, orig_to=<userB@company.eu>, relay=dovecot, delay=0.19, delays=0.16/0/0/0.03, dsn=2.0.0, status=sent (delivered via dovecot service)", Sequence{},
		// },

		{
			"json",
			`{"log-level":"INFO","message":"request/response","uri":"/ping","request":{"ssl-client-cert":null,"remote-addr":"10.11.22.33","headers":{"host":"itsman.staging.quinpress.com"},"server-port":3030,"content-length":null,"content-type":null,"character-encoding":null,"uri":"/ping","server-name":"xxxx.staging.strace.io","query-string":null,"body":"org.eclipse.jetty.server.HttpInput@51383a10","scheme":"http","request-method":"get"},"response":{"status":200,"body":"pong","headers":{"Access-Control-Allow-Origin":"*","content-type":"text/plain"}},"start-ts":1422427444553,"end-ts":1422427444554,"elapsed":1}`, Sequence{
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "log-level", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "INFO", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "message", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request/response", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "uri", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "/ping", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.ssl-client-cert", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "null", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.remote-addr", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "10.11.22.33", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.headers.host", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "itsman.staging.quinpress.com", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.server-port", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "3030", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.content-length", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "null", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.content-type", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "null", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.character-encoding", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "null", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.uri", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "/ping", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.server-name", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "xxxx.staging.strace.io", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.query-string", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "null", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.body", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "org.eclipse.jetty.server.HttpInput@51383a10", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.scheme", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "http", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "request.request-method", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "get", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "response.status", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "200", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "response.body", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "pong", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "response.headers.Access-Control-Allow-Origin", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "*", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "response.headers.content-type", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "text/plain", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "start-ts", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "1422427444553", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "end-ts", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "1422427444554", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "elapsed", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "1", isKey: false, isValue: true},
			},
		},

		{
			"json",
			`{"EventTime":"2014-08-16T12:45:03-0400","URI":"myuri","uri_payload":{"value":[{"open":"2014-08-16T13:00:00.000+0000","close":"2014-08-16T23:00:00.000+0000","isOpen":true,"date":"2014-08-16"}],"Count":1}}`, Sequence{
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "EventTime", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2014-08-16T12:45:03-0400", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "URI", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "myuri", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "uri_payload.value.0.open", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2014-08-16T13:00:00.000+0000", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "uri_payload.value.0.close", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2014-08-16T23:00:00.000+0000", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "uri_payload.value.0.isOpen", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "true", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "uri_payload.value.0.date", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2014-08-16", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "uri_payload.Count", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "1", isKey: false, isValue: true},
			},
		},

		//`{"syslogTime":"2014-04-10T17:17:13.696190-04:00","originName":"nl-fldi-00374.wdw.disney.com","message":{"X-Correlation-ID":"35b39f06-ca3e-4cc4-b02b-fd7506ca0df","level":"AUDIT","message":"Call Trace:\nSeverity: AUDIT\nX-Log-ID: b263b047-f807-49b4-b23e-f9e24cca4fe5\nX-Correlation-ID: 35b39f06-ca3e-4cc4-b02b-fd7506ca0df6\nX-System-ID: SF\nX-CAST-ID: null\nX-Guest-ID: null\nX-CIP: null\nX-Origin-System-ID: NGE-GXP.LOAD2-VALID\nTimestamp: Thu Apr 10 17:17:13 EDT 2014\nEndpoint: http:\/\/nge-load2.wdw.disney.com:8080\/assembly\/guest\/027BEF2F38EB424487092304E0532BA1\/identifiers\nHeaders: {Accept=[application\/json], apim-uuid=[35b39f06-ca3e-4cc4-b02b-fd7506ca0df6], Authorization=[BEARER _wRHo7wU6auBVDyYtOvPCw], client-ip=[10.52.27.19], Content-Type=[null], host=[nge-load2.wdw.disney.com:8080], lg_header=[Interaction=STyp79nmrokvRi5NRQFEDzIK;Locus=1dqc\/PEB1A2KXW9Je6ENpg==;Flow=cO_n26sYiatu6P5LRQH2DjIK;Chain=SDyp79nmrokvRi5NRQFEDzIK;UpstreamOpID=tfYAwD7njpLD4nyIgA9gbw==;Path=drlsVAS58dNUoEnn\/v0lwQ==;name=E_5400-4DCkv3.3sjnOcTwB-3D2123A0-INITIATED;CPTime=1397164633684;name=U_5400-4DCkv3.3sjnOcTwB-3D2123A0-COMPLETED;CPTime=1397164633684;CallerAddress=nl-fldi-01200;CalleeAddress=nge-load2.wdw.disney.com;], user-agent=[Jakarta Commons-HttpClient\/3.1], via=[http\/1.1 APIMClusterDISCPerfPROD-R2.7.1[FE800000000000000217A4FFFE770CB0] (ApacheTrafficServer\/3.2.0)], x-correlation-id=[35b39f06-ca3e-4cc4-b02b-fd7506ca0df6], x-expected-ttl=[5], x-ext-base-url=[http:\/\/nge-load2.wdw.disney.com:8080\/assembly], x-forwarded-for=[10.52.27.19], x-origin-system-id=[NGE-GXP.LOAD2-VALID]}\nHTTP Method: GET\nHTTP Request Parameters: \n\n","time":"2014-04-10T21:17:13.702Z","start_time":"2014-04-03T14:59:11.851Z","logger":"com.wdpr.nge.common.logging.appender.slf4j.SLF4JLogAppender","grid":"Dev","application":"sf-asm","appliance":"load2","thread":"tomcat-http--4015","file":"?","line":"?"}}`, Sequence{},

		{
			"json",
			`{"eventVersion": "1.0", "userIdentity": {"type": "IAMUser", "principalId": "EX_PRINCIPAL_ID", "arn": "arn:aws:iam::123456789012:user/Alice", "accessKeyId": "EXAMPLE_KEY_ID", "accountId": "123456789012", "userName": "Alice"}, "eventTime": "2014-03-06T21:22:54Z", "eventSource": "ec2.amazonaws.com", "eventName": "StartInstances", "awsRegion": "us-west-2", "sourceIPAddress": "205.251.233.176", "userAgent": "ec2-api-tools 1.6.12.2", "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-ebeaf9e2"}] } }, "responseElements": {"instancesSet": {"items": [{"instanceId": "i-ebeaf9e2", "currentState": {"code": 0, "name": "pending"}, "previousState": {"code": 80, "name": "stopped"} }] } } }`, Sequence{
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventVersion", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenFloat, Value: "1.0", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.type", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "IAMUser", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.principalId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "EX_PRINCIPAL_ID", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.arn", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "arn:aws:iam::123456789012:user/Alice", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.accessKeyId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "EXAMPLE_KEY_ID", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.accountId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "123456789012", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.userName", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Alice", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventTime", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2014-03-06T21:22:54Z", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventSource", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "ec2.amazonaws.com", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventName", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "StartInstances", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "awsRegion", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "us-west-2", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "sourceIPAddress", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "205.251.233.176", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userAgent", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "ec2-api-tools 1.6.12.2", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "requestParameters.instancesSet.items.0.instanceId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "i-ebeaf9e2", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "responseElements.instancesSet.items.0.instanceId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "i-ebeaf9e2", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "responseElements.instancesSet.items.0.currentState.code", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "0", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "responseElements.instancesSet.items.0.currentState.name", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "pending", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "responseElements.instancesSet.items.0.previousState.code", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "80", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "responseElements.instancesSet.items.0.previousState.name", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "stopped", isKey: false, isValue: true},
			},
		},

		{
			"json",
			`{"eventVersion": "1.01", "userIdentity": {"type": "IAMUser", "principalId": "XXXXXXXXXXXXXXXXXXXX", "arn": "arn:aws:iam::012345678901:user/rhendriks", "accountId": "012345678901", "accessKeyId": "XXXXXXXXXXXXXXXXXXXX", "userName": "rhendriks"}, "eventTime": "2014-01-31T12:00:00Z", "eventSource": "ec2.amazonaws.com", "eventName": "DescribeInstances", "awsRegion": "us-east-1", "sourceIPAddress": "11.111.111.111", "userAgent": "aws-sdk-ruby/1.33.0 ruby/1.9.3 x86_64-linux", "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-01234567"}] }, "filterSet": {} }, "responseElements": null, "requestID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaa", "eventID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaa"}`, Sequence{
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventVersion", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenFloat, Value: "1.01", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.type", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "IAMUser", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.principalId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "XXXXXXXXXXXXXXXXXXXX", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.arn", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "arn:aws:iam::012345678901:user/rhendriks", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.accountId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "012345678901", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.accessKeyId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "XXXXXXXXXXXXXXXXXXXX", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userIdentity.userName", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "rhendriks", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventTime", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2014-01-31T12:00:00Z", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventSource", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "ec2.amazonaws.com", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventName", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "DescribeInstances", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "awsRegion", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "us-east-1", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "sourceIPAddress", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenIPv4, Value: "11.111.111.111", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "userAgent", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "aws-sdk-ruby/1.33.0 ruby/1.9.3 x86_64-linux", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "requestParameters.instancesSet.items.0.instanceId", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "i-01234567", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "responseElements", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "null", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "requestID", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaa", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "eventID", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaa", isKey: false, isValue: true},
			},
		},

		{
			"json",
			`{"reference":"","roundTripDuration":206}`, Sequence{
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "roundTripDuration", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenInteger, Value: "206", isKey: false, isValue: true},
			},
		},

		{
			"json",
			`{"Version": "2012-10-17", "Statement": [{"Sid": "Put bucket policy needed for audit logging", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::193672423079:user/logs"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::AuditLogs/*"}, {"Sid": "Get bucket policy needed for audit logging ", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::193672423079:user/logs"}, "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::AuditLogs"} ] }`, Sequence{
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Version", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenTime, Value: "2012-10-17", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.0.Sid", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Put bucket policy needed for audit logging", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.0.Effect", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Allow", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.0.Principal.AWS", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "arn:aws:iam::193672423079:user/logs", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.0.Action", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "s3:PutObject", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.0.Resource", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "arn:aws:s3:::AuditLogs/*", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.1.Sid", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Get bucket policy needed for audit logging", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.1.Effect", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Allow", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.1.Principal.AWS", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "arn:aws:iam::193672423079:user/logs", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.1.Action", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "s3:GetBucketAcl", isKey: false, isValue: true},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "Statement.1.Resource", isKey: true, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "=", isKey: false, isValue: false},
				Token{Field: FieldUnknown, Type: TokenLiteral, Value: "arn:aws:s3:::AuditLogs", isKey: false, isValue: true},
			},
		},
	}
)
