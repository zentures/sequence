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
	"github.com/BurntSushi/toml"
	"github.com/surge/porter2"
)

var (
	tomlcfg map[string]map[string][]string

	Keymaps struct {
		Keywords map[string]FieldType
		Prekeys  map[string][]FieldType
	}
)

func init() {
	Keymaps.Keywords = make(map[string]FieldType)
	Keymaps.Prekeys = make(map[string][]FieldType)

	_, err := toml.Decode(defaultKeymapConfig, &tomlcfg)
	if err != nil {
		panic(err)
	}

	for w, list := range tomlcfg["keywords"] {
		if f := name2FieldType("%" + w + "%"); f != FieldUnknown {
			for _, kw := range list {
				pw := porter2.Stem(kw)
				Keymaps.Keywords[pw] = f
			}
		}
	}

	for w, m := range tomlcfg["prekeys"] {
		for _, fw := range m {
			if f := name2FieldType(fw); f != FieldUnknown {
				Keymaps.Prekeys[w] = append(Keymaps.Prekeys[w], f)
			}
		}
	}
}

var defaultKeymapConfig = `
[prekeys]
address		= [ "%srchost%", "%srcipv4%" ]
by 			= [ "%srchost%", "%srcipv4%", "%srcuser%" ]
command 	= [ "%command%" ]
connection 	= [ "%sessionid%" ]
dport		= [ "%dstport%" ]
dst 		= [ "%dsthost%", "%dstipv4%" ]
duration	= [ "%duration%" ]
egid 		= [ "%srcgid%" ]
euid 		= [ "%srcuid%" ]
for 		= [ "%srchost%", "%srcipv4%", "%srcuser%" ]
from 		= [ "%srchost%", "%srcipv4%" ]
gid 		= [ "%srcgid%" ]
group 		= [ "%srcgroup%" ]
logname 	= [ "%srcuser%" ]
port 		= [ "%srcport%", "%dstport%" ]
proto		= [ "%protocol%" ]
rhost 		= [ "%srchost%", "%srcipv4%" ]
ruser 		= [ "%srcuser%" ]
sport		= [ "%srcport%" ]
src 		= [ "%srchost%", "%srcipv4%" ]
time 		= [ "%msgtime%" ]
to 			= [ "%dsthost%", "%dstipv4%", "%dstuser%" ]
uid 		= [ "%srcuid%" ]
uname 		= [ "%srcuser%" ]
user 		= [ "%srcuser%" ]

[tags]
login 	= [ "login", "logon" ]
logout 	= [ "logout", "logoff" ]
failed 	= [ "failed", "failure", "fail" ]

[keywords]

action = [
	"access",
	"alert",
	"allocate",
	"allow",
	"audit",
	"authenticate",
	"backup",
	"bind",
	"block",
	"build",
	"built",
	"cancel",
	"clean",
	"close",
	"compress",
	"connect",
	"copy",
	"create",
	"decode",
	"decompress",
	"decrypt",
	"depress",
	"detect",
	"disconnect",
	"download",
	"encode",
	"encrypt",
	"establish",
	"execute",
	"filter",
	"find",
	"free",
	"get",
	"initialize",
	"initiate",
	"install",
	"lock",
	"login",
	"logoff",
	"logon",
	"logout",
	"modify",
	"move",
	"open",
	"post",
	"quarantine",
	"read",
	"release",
	"remove",
	"replicate",
	"resume",
	"save",
	"scan",
	"search",
	"start",
	"stop",
	"suspend",
	"teardown",
	"uninstall",
	"unlock",
	"update",
	"upgrade",
	"upload",
	"violate",
	"write"
]

status = [
	"accept",
	"error",
	"fail",
	"failure",
	"success"
]

object = [
	"account",
	"app",
	"bios",
	"driver",
	"email",
	"event",
	"file",
	"flow",
	"connection",
	"memory",
	"packet",
	"process",
	"rule",
	"session",
	"system",
	"thread",
	"vuln"
]

srcuser = [
	"root",
	"admin",
	"administrator"
]

method = [
	"password",
	"publickey"
]

protocol = [
	"udp",
	"tcp",
	"icmp",
	"http/1.0",
	"http/1.1"
]
`
