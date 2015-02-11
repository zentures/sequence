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
		msg, rule string
	}{
		{
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id = %appname% time = \" %msgtime% \" fw = %apphost% priv = %integer% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcipv4% sport = %srcport% dst = %dstipv4% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
		},
		{
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%msgtime% %apphost% %appname% : %method% ( ) , %string% fname = %string%",
		},
		{
			"may  2 15:51:24 dlfssrv unix: vfs root entry",
			"%msgtime% %apphost% %appname% : vfs root %action%",
		},
		{
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): conversation failed",
			"%msgtime% %apphost% %appname% : %method% ( %string% : %action% ) : conversation %status%",
		},
		{
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed",
			"%msgtime% %apphost% %appname% : %method% ( %string% : %action% ) : %string% %status%",
		},
		{
			"jan 15 14:07:35 testserver passwd: pam_unix(passwd:chauthtok): password changed for ustream",
			"%msgtime% %apphost% %appname% : %method% ( %string% : %action% ) : password changed for %dstuser%",
		},
		{
			"jan 15 19:15:55 jlz sshd[7106]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=188.65.16.110",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srcipv4%",
		},
		{
			"jan 15 19:25:56 jlz sshd[7774]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=stat.atomsib.net ",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srchost%",
		},
		{
			"Jan 12 10:38:51 irc sshd[7705]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=114.80.226.94  user=root",
			"%msgtime% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srcipv4% user = %dstuser%",
		},
		{
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection rate 1/60s for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%msgtime% %apphost% %appname% [ %integer% ] : statistics : max connection rate %string% for ( smtp : %appipv4% ) at %time%",
		},
		{
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection count 1 for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%msgtime% %apphost% %appname% [ %integer% ] : statistics : max connection count %integer% for ( smtp : %appipv4% ) at %time%",
		},
		{
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max cache size 1 at Jan 31 21:39:37",
			"%msgtime% %apphost% %appname% [ %integer% ] : statistics : max cache size %integer% at %time%",
		},
	}

	parsetests2 = []struct {
		msg, rule string
	}{
		{
			"jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream",
			"%msgtime% %apphost% %appname% : %srcuser% : tty = %string% ; pwd = %string% ; user = %dstuser% ; command = %method-%",
		},
		{
			"2015-02-11 11:04:40 H=(amoricanexpress.com) [64.20.195.132]:10246 F=<fxC4480@amoricanexpress.com> rejected RCPT <SCRUBBED@SCRUBBED.com>: Sender verify failed",
			"%msgtime% H = ( %srchost% ) [ %srcipv4% ] : %srcport% F = < %srcemail% > %action% RCPT < %dstemail% > : %reason-%",
		},
	}
)

func TestParserMatchPatterns(t *testing.T) {
	parser := NewParser()

	for _, tc := range parsetests {
		err := parser.Add(tc.rule)
		require.NoError(t, err, tc.rule)
	}

	for _, tc := range parsetests {
		seq, err := parser.Parse(tc.msg)
		require.NoError(t, err, tc.msg)
		require.Equal(t, tc.rule, seq.String(), seq.PrintTokens())
	}
}

func TestParserParseMessages(t *testing.T) {
	parser := NewParser()

	for _, tc := range parsetests2 {
		err := parser.Add(tc.rule)
		require.NoError(t, err, tc.rule)
	}

	for _, tc := range parsetests2 {
		_, err := parser.Parse(tc.msg)
		require.NoError(t, err, tc.msg)
		//glog.Debugln(seq.PrintTokens())
	}
}

func BenchmarkParser(b *testing.B) {
	parser := NewParser()
	parser.Add(parsetests[0].rule)

	for i := 0; i < b.N; i++ {
		parser.Parse(parsetests[0].msg)
	}
}
