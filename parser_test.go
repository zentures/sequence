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
	parsetests = []struct {
		format, msg, rule string
	}{
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id = %appname% time = \" %msgtime% \" fw = %apphost% priv = %integer% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcip% sport = %srcport% dst = %dstip% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%msgtime% %apphost% %appname% : %method% ( ) , %string% fname = %string%",
		},
		{
			"general",
			"may  2 15:51:24 dlfssrv unix: vfs root entry",
			"%msgtime% %apphost% %appname% : vfs root %action%",
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): conversation failed",
			"%msgtime% %apphost% %appname% : %method% ( %string% : %action% ) : conversation %status%",
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed",
			"%msgtime% %apphost% %appname% : %method% ( %string% : %action% ) : %string% %status%",
		},
		{
			"general",
			"jan 15 14:07:35 testserver passwd: pam_unix(passwd:chauthtok): password changed for ustream",
			"%msgtime% %apphost% %appname% : %method% ( %string% : %action% ) : password changed for %dstuser%",
		},
		{
			"general",
			"jan 15 19:15:55 jlz sshd[7106]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=188.65.16.110",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srcip%",
		},
		{
			"general",
			"jan 15 19:25:56 jlz sshd[7774]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=stat.atomsib.net ",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srchost%",
		},
		{
			"general",
			"Jan 12 10:38:51 irc sshd[7705]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=114.80.226.94  user=root",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srcip% user = %dstuser%",
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection rate 1/60s for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%msgtime% %apphost% %appname% [ %integer% ] : statistics : max connection rate %string% for ( smtp : %appip% ) at %time%",
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection count 1 for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%msgtime% %apphost% %appname% [ %integer% ] : statistics : max connection count %integer% for ( smtp : %appip% ) at %time%",
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max cache size 1 at Jan 31 21:39:37",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : statistics : max cache size %integer% at %time%",
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606.4]: statistics: max cache size 1 at Jan 31 21:39:37",
			"%msgtime% %apphost% %appname% [ %sessionid:float% ] : statistics : max cache size %integer% at %time%",
		},
		{
			"general",
			"Feb 06 13:37:00 box sshd[4388]: Accepted publickey for cryptix from dead:beef:1234:5678:223:32ff:feb1:2e50 port 58251 ssh2: RSA de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : accepted publickey for %dstuser% from %srcip:ipv6% port %integer% ssh2 : rsa %string%",
		},
		{
			"general",
			"Feb 06 13:37:00 box sshd[4388]: Accepted publickey for cryptix from 192.168.1.1 port 58251 ssh2: RSA de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : accepted publickey for %dstuser% from %srcip% port %integer% ssh2 : rsa %string%",
		},
		// relates to #7
		{
			"general",
			"Feb  8 12:15:52 mail postfix/pipe[76139]: 499F62D65: to=<userA@company.office>, orig_to=<alias24@alias.com>, relay=dovecot, delay=0.24, delays=0.21/0/0/0.04, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %msgid% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %float% , delays = %string% , dsn = %string% , status = %status% ( %reason::*% )",
		},
		{
			"general",
			"Feb  8 21:51:10 mail postfix/pipe[84059]: 440682230: to=<userB@company.office>, orig_to=<userB@company.biz>, relay=dovecot, delay=0.9, delays=0.87/0/0/0.03, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %msgid:integer% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %float% , delays = %string% , dsn = %string% , status = %status% ( %reason::+% )",
		},
		{
			"general",
			"Feb  8 21:51:10 mail postfix/pipe[84059]: 440682230: to=<userB@company.office>, orig_to=<userB@company.biz>, relay=dovecot, delay=1, delays=0.87/0/0/0.03, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %msgid:integer% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %integer% , delays = %string% , dsn = %string% , status = %status% ( %reason::+% )",
		},
		{
			"general",
			"jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream",
			"%msgtime% %apphost% %appname% : %srcuser% : tty = %string% ; pwd = %string% ; user = %dstuser% ; command = %method::-%",
		},
		{
			"general",
			"2015-02-11 11:04:40 H=(amoricanexpress.com) [64.20.195.132]:10246 F=<fxC4480@amoricanexpress.com> rejected RCPT <SCRUBBED@SCRUBBED.com>: Sender verify failed",
			"%msgtime% h = ( %srchost% ) [ %srcip% ] : %srcport% f = < %srcemail% > %action% rcpt < %dstemail% > : %reason::-%",
		},
		{
			"json",
			`{"reference":"","roundTripDuration":206}`,
			"roundtripduration = %duration%",
		},
		{
			"json",
			`{"EventTime":"2014-08-16T12:45:03-0400","URI":"myuri","uri_payload":{"value":[{"open":"2014-08-16T13:00:00.000+0000","close":"2014-08-16T23:00:00.000+0000","isOpen":true,"date":"2014-08-16"}],"Count":1}}`,
			"eventtime = %msgtime% uri = %object% uri_payload.value.0.open = %time% uri_payload.value.0.close = %time% uri_payload.value.0.isopen = %string% uri_payload.value.0.date = %time% uri_payload.count = %integer%",
		},
	}

	parsetests2 = []struct {
		format, msg, rule string
	}{
		// relates to #5
		{
			"general",
			"Feb  8 12:15:52 mail postfix/pipe[76139]: 499F62D65: to=<userA@company.office>, orig_to=<alias24@alias.com>, relay=dovecot, delay=0.24, delays=0.21/0/0/0.04, dsn=2.0.0, status=sent ()",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %msgid% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %float% , delays = %string% , dsn = %string% , status = %status% ( %reason::*% )",
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%msgtime% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:*%",
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%msgtime% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:+%",
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile - abc",
			"%msgtime% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:+%",
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile - abc",
			"%msgtime% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:-%",
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=",
			"%msgtime% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:*%",
		},
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv= recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id = %appname% time = \" %msgtime% \" fw = %apphost% priv = %integer:*% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcip% sport = %srcport% dst = %dstip% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
		},
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id = %appname% time = \" %msgtime% \" fw = %apphost% priv = %integer:*% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcip% sport = %srcport% dst = %dstip% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
		},
		{
			"general",
			"jan 15 14:07:04 testserver : pam_unix(sudo:auth): password failed",
			"%msgtime% %apphost% %appname:*% : %method% ( %string% : %action% ) : %string% %status%",
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password",
			"%msgtime% %apphost% %appname% : %method% ( %string% : %action% ) : %string:*% %status%",
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed",
			"%msgtime% %apphost% %appname% : %method:+% ( %string% : %action% ) : %string% %status%",
		},
		{
			"general",
			"jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream",
			"%msgtime% %apphost% %appname% : %srcuser% : tty = %string% ; pwd = %string% ; user = %dstuser% ; command = %method::-%",
		},
	}
)

func init() {
	if err := ReadConfig("sequence.toml"); err != nil {
		panic(err)
	}
}

func TestParserMatchPatterns(t *testing.T) {
	parser := NewGeneralParser()
	scanner := NewScanner()

	var (
		seq Sequence
		err error
	)

	for _, tc := range parsetests {
		seq, err := scanner.Scan(tc.rule)
		require.NoError(t, err, tc.rule)
		err = parser.Add(seq)
		require.NoError(t, err, tc.rule)
	}

	for _, tc := range parsetests {
		switch tc.format {
		case "json":
			seq, err = scanner.ScanJson(tc.msg)

		default:
			seq, err = scanner.Scan(tc.msg)
		}

		require.NoError(t, err, tc.msg)
		seq, err = parser.Parse(seq)
		require.NoError(t, err, tc.msg)
		require.Equal(t, tc.rule, seq.String(), tc.msg+"\n"+seq.PrintTokens())
	}
}

func TestParserParseMessages(t *testing.T) {
	parser := NewGeneralParser()
	scanner := NewScanner()

	var (
		seq Sequence
		err error
	)

	for _, tc := range parsetests2 {
		seq, err := scanner.Scan(tc.rule)
		require.NoError(t, err, tc.rule)
		err = parser.Add(seq)
		require.NoError(t, err, tc.rule)
	}

	for _, tc := range parsetests2 {
		switch tc.format {
		case "json":
			seq, err = scanner.ScanJson(tc.msg)

		default:
			seq, err = scanner.Scan(tc.msg)
		}

		require.NoError(t, err, tc.msg)
		seq, err = parser.Parse(seq)
		require.NoError(t, err, tc.msg)
	}
}

func BenchmarkParserParseMeta(b *testing.B) {
	benchmarkRunParser(b, parsetests2[3])
}

func BenchmarkParserParseNoMeta(b *testing.B) {
	benchmarkRunParser(b, parsetests[1])
}

func benchmarkRunParser(b *testing.B, tc struct{ format, msg, rule string }) {
	parser := NewGeneralParser()
	scanner := NewScanner()

	seq, _ := scanner.Scan(tc.rule)
	parser.Add(seq)

	seq, _ = scanner.Scan(tc.msg)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parser.Parse(seq)
	}
}
