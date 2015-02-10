sequence
========

[![GoDoc](http://godoc.org/github.com/strace/sequence?status.svg)](http://godoc.org/github.com/strace/sequence) 

[![GoDoc](http://godoc.org/github.com/strace/sequence/sequence?status.svg)](http://godoc.org/github.com/strace/sequence/sequence)

`sequence` is a _high performance sequential log parser_. It _sequentially_ goes through a log message, _parses_ out the meaningful parts, without the use regular expressions. It can achieve _high performance_ parsing of **100,000 - 200,000 messages per second (MPS)** without the need to separate parsing rules by log source type.

**`sequence` is currently under active development and should be considered unstable until further notice.**

**If you have a set of logs you would like me to test out, please feel free to [open an issue](https://github.com/strace/sequence/issues) and we can arrange a way for me to download and test your logs.**

### Motivation

Log messages are notoriusly difficult to parse because they all have different formats. Industries (see Splunk, ArcSight, Tibco LogLogic, Sumo Logic, Logentries, Loggly, LogRhythm, etc etc etc) have been built to solve the problems of parsing, understanding and analyzing log messages.

Let's say you have a bunch of log files you like to parse. The first problem you will typically run into is you have no way of telling how many DIFFERENT types of messages there are, so you have no idea how much work there will be to develop rules to parse all the messages. Not only that, you have hundreds of thousands, if not  millions of messages, in front of you, and you have no idea what messages are worth parsing, and what's not.

The typical workflow is develop a set of regular expressions and keeps testing against the logs until some magical moment where all the logs you want parsed are parsed. Ask anyone who does this for a living and they will tell you this process is long, frustrating and error-prone.

Even after you have developed a set of regular expressions that match the original set of messages, if new messages come in, you will have to determine which of the new messages need to be parsed. And if you develop a new set of regular expressions to parse those new messages, you still have no idea if the regular expressions will conflict with the ones you wrote before. If you write your regex parsers too liberally, it can easily parse the wrong messages.

After all that, you will end up finding out the regex parsers are quite slow. It can typically parse several thousands messages per second. Given enough CPU resources on a large enough machine, regex parsers can probably parse tens of thousands of messages per second. Even to achieve this type of performance, you will likely need to limit the number of regular expressions the parser has. The more regex rules, the slower the parser will go.

To work around this performance issue, companies have tried to separate the regex rules for different log message types into different parsers. For example, they will have a parser for Cisco ASA logs, a parser for sshd logs, a parser for Apache logs, etc etc. And then they will require the users to tell them which parser to use (usually by indicating the log source type of the originating IP address or host.)

Sequence is developed to make analyzing and parsing log messages a lot easier and faster.

### Performance

The following performance benchmarks are run on a single 4-core (2.8Ghz i7) MacBook Pro, although the tests were only using 1 or 2 cores. The first file is a bunch of sshd logs, averaging 98 bytes per message. The second is a Cisco ASA log file, averaging 180 bytes per message. Last is a mix of ASA, sshd and sudo logs, averaging 136 bytes per message.

```
  $ ./sequence bench -p ../../patterns/sshd.txt -i ../../data/sshd.all
  Parsed 212897 messages in 1.69 secs, ~ 126319.27 msgs/sec

  $ ./sequence bench -p ../../patterns/asa.txt -i ../../data/allasa.log
  Parsed 234815 messages in 2.89 secs, ~ 81323.41 msgs/sec

  $ ./sequence bench -d ../patterns -i ../data/asasshsudo.log
  Parsed 447745 messages in 4.47 secs, ~ 100159.65 msgs/sec
```

Performance can be improved by adding more cores:

```
  GOMAXPROCS=2 ./sequence bench -p ../../patterns/sshd.txt -i ../../data/sshd.all -w 2
  Parsed 212897 messages in 1.00 secs, ~ 212711.83 msgs/sec

  $ GOMAXPROCS=2 ./sequence bench -p ../../patterns/asa.txt -i ../../data/allasa.log -w 2
  Parsed 234815 messages in 1.56 secs, ~ 150769.68 msgs/sec

  $ GOMAXPROCS=2 ./sequence bench -d ../patterns -i ../data/asasshsudo.log -w 2
  Parsed 447745 messages in 2.52 secs, ~ 177875.94 msgs/sec
```

### Limitations

* `sequence` does not handle multi-line logs. Each log message must appear as a single line. So if there's multi-line logs, they must be first be converted into a single line.
* `sequence` has been only tested with a limited set of system (Linux, AIX, sudo, ssh, su, dhcp, etc etc), network (ASA, PIX, Neoteris, CheckPoint, Juniper Firewall) and infrastructure application (apache, bluecoat, etc) logs. If you have a set of logs you would like me to test out, please feel free to [open an issue](https://github.com/strace/sequence/issues) and we can arrange a way for me to download and test your logs.

### Usage

To run the unit tests, you need to be in the top level sequence dir:

```
go get github.com/strace/sequence
cd $GOPATH/src/github.com/strace/sequence
go test
```

To run the actual command you need to

```
cd $GOPATH/src/github.com/strace/sequence/cmd/sequence
go run sequence.go
```

### Documentation

Documentation is available at godoc: [package](http://godoc.org/github.com/strace/sequence), [command](http://godoc.org/github.com/strace/sequence/sequence).

### License

Copyright (c) 2014 Dataence, LLC. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

### Roadmap / Futures

There are some pattern files developed for ASA, Sudo and SSH in the `patterns` directory. The goal is to continue to develop a set of patterns for the various log messages, and along the way add additional features to the parser that can help make it even easier to parse log messages. So currently there's not a set roadmap.

## Concepts

The following concepts are part of the package:

- A _Token_ is a piece of information extracted from the original log message. It is a struct that contains fields for _TokenType_, _FieldType_, _Value_, and indicators of whether it's a key or value in the key=value pair.

- A _TokenType_ indicates whether the token is a literal string (one that does not change), a variable string (one that could have different values), an IPv4 or IPv6 address, a MAC address, an integer, a floating point number, or a timestamp.

- A _FieldType_ indicates the semantic meaning of the token. For example, a token could be a source IP address (%srcipv4%), or a user (%srcuser% or %dstuser%), an action (%action%) or a status (%status%).

- A _Sequence_ is a list of Tokens. It is returned by the _Tokenizer_, and the _Parser_.

- A _Scanner_ is a sequential lexical analyzer that breaks a log message into a sequence of tokens. It is sequential because it goes through log message sequentially tokentizing each part of the message, without the use of regular expressions. The scanner currently recognizes time stamps, IPv4 addresses, URLs, MAC addresses,
integers and floating point numbers. 

- A _Analyzer_ builds an analysis tree that represents all the Sequences from messages. It can be used to determine all of the unique patterns for a large body of messages.

- A _Parser_ is a tree-based parsing engine for log messages. It builds a parsing tree based on pattern sequence supplied, and for each message sequence, returns the matching pattern sequence. Each of the message tokens will be marked with the semantic field types.

## Sequence Command

The `sequence` command is developed to demonstrate the use of this package. You can find it in the `sequence` directory. The `sequence` command implements the _sequential semantic log parser_.

```
   Usage:
     sequence [command]

   Available Commands:
     scan                      scan will tokenize a log file or message and output a list of tokens
     analyze                   analyze will analyze a log file and output a list of patterns that will match all the log messages
     parse                     parse will parse a log file and output a list of parsed tokens for each of the log messages
     bench                     benchmark the parsing of a log file, no output is provided
     help [command]            Help about any command
```

### Scan

```
  Usage:
    sequence scan [flags]

   Available Flags:
    -h, --help=false: help for scan
    -m, --msg="": message to tokenize
```

Example

```
  $ ./sequence scan -m "jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream"
  #   0: { Field="%funknown%", Type="%ts%", Value="jan 14 10:15:56" }
  #   1: { Field="%funknown%", Type="%literal%", Value="testserver" }
  #   2: { Field="%funknown%", Type="%literal%", Value="sudo" }
  #   3: { Field="%funknown%", Type="%literal%", Value=":" }
  #   4: { Field="%funknown%", Type="%literal%", Value="gonner" }
  #   5: { Field="%funknown%", Type="%literal%", Value=":" }
  #   6: { Field="%funknown%", Type="%literal%", Value="tty" }
  #   7: { Field="%funknown%", Type="%literal%", Value="=" }
  #   8: { Field="%funknown%", Type="%string%", Value="pts/3" }
  #   9: { Field="%funknown%", Type="%literal%", Value=";" }
  #  10: { Field="%funknown%", Type="%literal%", Value="pwd" }
  #  11: { Field="%funknown%", Type="%literal%", Value="=" }
  #  12: { Field="%funknown%", Type="%string%", Value="/home/gonner" }
  #  13: { Field="%funknown%", Type="%literal%", Value=";" }
  #  14: { Field="%funknown%", Type="%literal%", Value="user" }
  #  15: { Field="%funknown%", Type="%literal%", Value="=" }
  #  16: { Field="%funknown%", Type="%string%", Value="root" }
  #  17: { Field="%funknown%", Type="%literal%", Value=";" }
  #  18: { Field="%funknown%", Type="%literal%", Value="command" }
  #  19: { Field="%funknown%", Type="%literal%", Value="=" }
  #  20: { Field="%funknown%", Type="%string%", Value="/bin/su" }
  #  21: { Field="%funknown%", Type="%literal%", Value="-" }
  #  22: { Field="%funknown%", Type="%literal%", Value="ustream" }
```

### Analyze

```
  Usage:
    sequence analyze [flags]

   Available Flags:
    -h, --help=false: help for analyze
    -i, --infile="": input file, required
    -o, --outfile="": output file, if empty, to stdout
    -d, --patdir="": pattern directory,, all files in directory will be used, optional
    -p, --patfile="": initial pattern file, optional
```

The following command analyzes a set of sshd log messages, and output the
patterns to the sshd.pat file. In this example, `sequence` analyzed over 200K
messages and found 45 unique patterns. Notice we are not supplying an existing
pattern file, so it treats all the patters as new.

```
  $ ./sequence analyze -i ../../data/sshd.all  -o sshd.pat
  Analyzed 212897 messages, found 45 unique patterns, 45 are new.
```

And the output file has entries such as:

```
  %msgtime% %apphost% %appname% [ %sessionid% ] : %status% %method% for %srcuser% from %srcipv4% port %srcport% ssh2
  # Jan 15 19:39:26 irc sshd[7778]: Accepted password for jlz from 108.61.8.124 port 57630 ssh2
```

The Analyzer tries to guess to the best of its ability on the type of tokens it encounters. It can probably guess 50-60% but can often guess wrong. For example

```
  %msgtime% %apphost% %appname% [ %sessionid% ] : %status% %method% for %srcuser% %string% %action% from %srcipv4% port %srcport% ssh2
  # Jan 15 18:25:24 jlz sshd[3721]: Failed password for invalid user building from 188.65.16.110 port 58375 ssh2
```

In the above message, the token `invalid` is mistakenly guesssed as `%srcuser%` because it follows the keyword `for`, as defined in [keymaps.go](https://github.com/strace/sequence/blob/master/keymaps.go). 

However, the analyzer should help reduce the amount of effort in writing rules. Also, once some of the patterns are established, there should be fewer new ones you need to write. For example, in the following command, we added an existing pattern file to the mix, which has a set of existing rules. Notice now there are only 35 unique patterns, and we were able to parse all of the log messages (no new patterns). There are fewer patterns
because some of the patterns were combined.

```
  $ ./sequence analyze -d ../../patterns -i ../../data/sshd.all  -o sshd.pat
  Analyzed 212897 messages, found 35 unique patterns, 0 are new.
```

### Parse

```
  Usage:
    sequence parse [flags]

   Available Flags:
    -h, --help=false: help for parse
    -i, --infile="": input file, required
    -o, --outfile="": output file, if empty, to stdout
    -d, --patdir="": pattern directory,, all files in directory will be used
    -p, --patfile="": initial pattern file, required
```

The following command parses a file based on existing rules. Note that the
performance number (9570.20 msgs/sec) is mostly due to reading/writing to disk.
To get a more realistic performance number, see the benchmark section below.

```
  $ ./sequence parse -d ../../patterns -i ../../data/sshd.all  -o parsed.sshd
  Parsed 212897 messages in 22.25 secs, ~ 9570.20 msgs/sec
```

This is an entry from the output file:

```
  Jan 15 19:39:26 jlz sshd[7778]: pam_unix(sshd:session): session opened for user jlz by (uid=0)
  #   0: { Field="%createtime%", Type="%ts%", Value="jan 15 19:39:26" }
  #   1: { Field="%apphost%", Type="%string%", Value="jlz" }
  #   2: { Field="%appname%", Type="%string%", Value="sshd" }
  #   3: { Field="%funknown%", Type="%literal%", Value="[" }
  #   4: { Field="%sessionid%", Type="%integer%", Value="7778" }
  #   5: { Field="%funknown%", Type="%literal%", Value="]" }
  #   6: { Field="%funknown%", Type="%literal%", Value=":" }
  #   7: { Field="%funknown%", Type="%string%", Value="pam_unix" }
  #   8: { Field="%funknown%", Type="%literal%", Value="(" }
  #   9: { Field="%funknown%", Type="%literal%", Value="sshd" }
  #  10: { Field="%funknown%", Type="%literal%", Value=":" }
  #  11: { Field="%funknown%", Type="%string%", Value="session" }
  #  12: { Field="%funknown%", Type="%literal%", Value=")" }
  #  13: { Field="%funknown%", Type="%literal%", Value=":" }
  #  14: { Field="%object%", Type="%string%", Value="session" }
  #  15: { Field="%action%", Type="%string%", Value="opened" }
  #  16: { Field="%funknown%", Type="%literal%", Value="for" }
  #  17: { Field="%funknown%", Type="%literal%", Value="user" }
  #  18: { Field="%dstuser%", Type="%string%", Value="jlz" }
  #  19: { Field="%funknown%", Type="%literal%", Value="by" }
  #  20: { Field="%funknown%", Type="%literal%", Value="(" }
  #  21: { Field="%funknown%", Type="%literal%", Value="uid" }
  #  22: { Field="%funknown%", Type="%literal%", Value="=" }
  #  23: { Field="%funknown%", Type="%integer%", Value="0" }
  #  24: { Field="%funknown%", Type="%literal%", Value=")" }
```

### Benchmark

```
  Usage:
    sequence bench [flags]

   Available Flags:
    -c, --cpuprofile="": CPU profile filename
    -h, --help=false: help for bench
    -i, --infile="": input file, required
    -d, --patdir="": pattern directory,, all files in directory will be used
    -p, --patfile="": pattern file, required
    -w, --workers=1: number of parsing workers
```

The following command will benchmark the parsing of two files. First file is a
bunch of sshd logs, averaging 98 bytes per message. The second is a Cisco ASA
log file, averaging 180 bytes per message.

```
  $ ./sequence bench -p ../../patterns/sshd.txt -i ../../data/sshd.all
  Parsed 212897 messages in 1.69 secs, ~ 126319.27 msgs/sec

  $ ./sequence bench -p ../../patterns/asa.txt -i ../../data/allasa.log
  Parsed 234815 messages in 2.89 secs, ~ 81323.41 msgs/sec
```

Performance can be improved by adding more cores:

```
  GOMAXPROCS=2 ./sequence bench -p ../../patterns/sshd.txt -i ../../data/sshd.all -w 2
  Parsed 212897 messages in 1.00 secs, ~ 212711.83 msgs/sec

  $ GOMAXPROCS=2 ./sequence bench -p ../../patterns/asa.txt -i ../../data/allasa.log -w 2
  Parsed 234815 messages in 1.56 secs, ~ 150769.68 msgs/sec
```
