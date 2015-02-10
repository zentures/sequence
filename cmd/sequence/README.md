sequence
========

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