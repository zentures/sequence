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

// The `sequence` command implements a _sequential semantic log parser_.
//
// It is _sequential_ because it goes through a log message sequentially and does not
// use regular expressions. It is _semantic_ because it tries to extract meaningful
// information out of the log messages and give them semantic indicators, e.g.,
// src IPv4 or dst IPv4. It is a _parser_ because it will take a message and parses
// out the meaningful parts.
//
//    Usage:
//      sequence [command]
//
//    Available Commands:
//      scan                      scan will tokenize a log file or message and output a list of tokens
//      parse                     parse will parse a log file and output a list of parsed tokens for each of the log messages
//      bench                     benchmark the parsing of a log file, no output is provided
//      help [command]            Help about any command
//
// ### Scan
//
//   Usage:
//     sequence scan [flags]
//
//    Available Flags:
//     -h, --help=false: help for scan
//     -m, --msg="": message to tokenize
//
// Example
//
//   $ ./sequence scan -m "jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream"
//   #   0: { Field="%funknown%", Type="%ts%", Value="jan 14 10:15:56" }
//   #   1: { Field="%funknown%", Type="%literal%", Value="testserver" }
//   #   2: { Field="%funknown%", Type="%literal%", Value="sudo" }
//   #   3: { Field="%funknown%", Type="%literal%", Value=":" }
//   #   4: { Field="%funknown%", Type="%literal%", Value="gonner" }
//   #   5: { Field="%funknown%", Type="%literal%", Value=":" }
//   #   6: { Field="%funknown%", Type="%literal%", Value="tty" }
//   #   7: { Field="%funknown%", Type="%literal%", Value="=" }
//   #   8: { Field="%funknown%", Type="%string%", Value="pts/3" }
//   #   9: { Field="%funknown%", Type="%literal%", Value=";" }
//   #  10: { Field="%funknown%", Type="%literal%", Value="pwd" }
//   #  11: { Field="%funknown%", Type="%literal%", Value="=" }
//   #  12: { Field="%funknown%", Type="%string%", Value="/home/gonner" }
//   #  13: { Field="%funknown%", Type="%literal%", Value=";" }
//   #  14: { Field="%funknown%", Type="%literal%", Value="user" }
//   #  15: { Field="%funknown%", Type="%literal%", Value="=" }
//   #  16: { Field="%funknown%", Type="%string%", Value="root" }
//   #  17: { Field="%funknown%", Type="%literal%", Value=";" }
//   #  18: { Field="%funknown%", Type="%literal%", Value="command" }
//   #  19: { Field="%funknown%", Type="%literal%", Value="=" }
//   #  20: { Field="%funknown%", Type="%string%", Value="/bin/su" }
//   #  21: { Field="%funknown%", Type="%literal%", Value="-" }
//   #  22: { Field="%funknown%", Type="%literal%", Value="ustream" }
//
// ### Parse
//
//   Usage:
//     sequence parse [flags]
//
//    Available Flags:
//     -h, --help=false: help for parse
//     -i, --infile="": input file, required
//     -o, --outfile="": output file, if empty, to stdout
//     -d, --patdir="": pattern directory,, all files in directory will be used
//     -p, --patfile="": initial pattern file, required
//
// The following command parses a file based on existing rules. Note that the
// performance number (9570.20 msgs/sec) is mostly due to reading/writing to disk.
// To get a more realistic performance number, see the benchmark section below.
//
//   $ ./sequence parse -d ../../patterns -i ../../data/sshd.all  -o parsed.sshd
//   Parsed 212897 messages in 22.25 secs, ~ 9570.20 msgs/sec
//
// This is an entry from the output file:
//
//   Jan 15 19:39:26 jlz sshd[7778]: pam_unix(sshd:session): session opened for user jlz by (uid=0)
//   #   0: { Field="%createtime%", Type="%ts%", Value="jan 15 19:39:26" }
//   #   1: { Field="%apphost%", Type="%string%", Value="jlz" }
//   #   2: { Field="%appname%", Type="%string%", Value="sshd" }
//   #   3: { Field="%funknown%", Type="%literal%", Value="[" }
//   #   4: { Field="%sessionid%", Type="%integer%", Value="7778" }
//   #   5: { Field="%funknown%", Type="%literal%", Value="]" }
//   #   6: { Field="%funknown%", Type="%literal%", Value=":" }
//   #   7: { Field="%funknown%", Type="%string%", Value="pam_unix" }
//   #   8: { Field="%funknown%", Type="%literal%", Value="(" }
//   #   9: { Field="%funknown%", Type="%literal%", Value="sshd" }
//   #  10: { Field="%funknown%", Type="%literal%", Value=":" }
//   #  11: { Field="%funknown%", Type="%string%", Value="session" }
//   #  12: { Field="%funknown%", Type="%literal%", Value=")" }
//   #  13: { Field="%funknown%", Type="%literal%", Value=":" }
//   #  14: { Field="%object%", Type="%string%", Value="session" }
//   #  15: { Field="%action%", Type="%string%", Value="opened" }
//   #  16: { Field="%funknown%", Type="%literal%", Value="for" }
//   #  17: { Field="%funknown%", Type="%literal%", Value="user" }
//   #  18: { Field="%dstuser%", Type="%string%", Value="jlz" }
//   #  19: { Field="%funknown%", Type="%literal%", Value="by" }
//   #  20: { Field="%funknown%", Type="%literal%", Value="(" }
//   #  21: { Field="%funknown%", Type="%literal%", Value="uid" }
//   #  22: { Field="%funknown%", Type="%literal%", Value="=" }
//   #  23: { Field="%funknown%", Type="%integer%", Value="0" }
//   #  24: { Field="%funknown%", Type="%literal%", Value=")" }
//
// ### Benchmark
//
//   Usage:
//     sequence bench [flags]
//
//    Available Flags:
//     -c, --cpuprofile="": CPU profile filename
//     -h, --help=false: help for bench
//     -i, --infile="": input file, required
//     -d, --patdir="": pattern directory,, all files in directory will be used
//     -p, --patfile="": pattern file, required
//     -w, --workers=1: number of parsing workers
//
// The following command will benchmark the parsing of two files. First file is a
// bunch of sshd logs, averaging 98 bytes per message. The second is a Cisco ASA
// log file, averaging 180 bytes per message.
//
//   $ ./sequence bench -p ../../patterns/sshd.txt -i ../../data/sshd.all
//   Parsed 212897 messages in 1.69 secs, ~ 126319.27 msgs/sec
//
//   $ ./sequence bench -p ../../patterns/asa.txt -i ../../data/allasa.log
//   Parsed 234815 messages in 2.89 secs, ~ 81323.41 msgs/sec
//
// Performance can be improved by adding more cores:
//
//   GOMAXPROCS=2 ./sequence bench -p ../../patterns/sshd.txt -i ../../data/sshd.all -w 2
//   Parsed 212897 messages in 1.00 secs, ~ 212711.83 msgs/sec
//
//   $ GOMAXPROCS=2 ./sequence bench -p ../../patterns/asa.txt -i ../../data/allasa.log -w 2
//   Parsed 234815 messages in 1.56 secs, ~ 150769.68 msgs/sec
package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/strace/sequence"
	"github.com/surge/glog"
)

var (
	sequenceCmd = &cobra.Command{
		Use:   "sequence",
		Short: "sequence is a sequenceial semantic log analyzer and analyzer",
	}

	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "scan will tokenize a log file or message and output a list of tokens",
	}

	parseCmd = &cobra.Command{
		Use:   "parse",
		Short: "parse will parse a log file and output a list of parsed tokens for each of the log messages",
	}

	benchCmd = &cobra.Command{
		Use:   "bench",
		Short: "benchmark the parsing of a log file, no output is provided",
	}

	inmsg      string
	infile     string
	outfile    string
	patfile    string
	patdir     string
	cpuprofile string
	workers    int

	quit chan struct{}
	done chan struct{}
)

func init() {
	quit = make(chan struct{})
	done = make(chan struct{})

	scanCmd.Flags().StringVarP(&inmsg, "msg", "m", "", "message to tokenize")
	scanCmd.Run = scan

	parseCmd.Flags().StringVarP(&infile, "infile", "i", "", "input file, required ")
	parseCmd.Flags().StringVarP(&patfile, "patfile", "p", "", "initial pattern file, required")
	parseCmd.Flags().StringVarP(&patdir, "patdir", "d", "", "pattern directory,, all files in directory will be used")
	parseCmd.Flags().StringVarP(&outfile, "outfile", "o", "", "output file, if empty, to stdout")
	parseCmd.Run = parse

	benchCmd.Flags().StringVarP(&infile, "infile", "i", "", "input file, required ")
	benchCmd.Flags().StringVarP(&patfile, "patfile", "p", "", "pattern file, required")
	benchCmd.Flags().StringVarP(&patdir, "patdir", "d", "", "pattern directory,, all files in directory will be used")
	benchCmd.Flags().StringVarP(&cpuprofile, "cpuprofile", "c", "", "CPU profile filename")
	benchCmd.Flags().IntVarP(&workers, "workers", "w", 1, "number of parsing workers")
	benchCmd.Run = bench

	sequenceCmd.AddCommand(scanCmd)
	sequenceCmd.AddCommand(parseCmd)
	sequenceCmd.AddCommand(benchCmd)
}

func profile() {
	var f *os.File
	var err error

	if cpuprofile != "" {
		f, err = os.Create(cpuprofile)
		if err != nil {
			log.Fatal(err)
		}

		pprof.StartCPUProfile(f)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, os.Kill)
	go func() {
		select {
		case sig := <-sigchan:
			log.Printf("Existing due to trapped signal; %v", sig)

		case <-quit:
			log.Println("Quiting...")

		}

		if f != nil {
			glog.Errorf("Stopping profile")
			pprof.StopCPUProfile()
			f.Close()
		}

		close(done)
		os.Exit(0)
	}()
}

func scan(cmd *cobra.Command, args []string) {
	msg := &sequence.Message{}
	seq, err := msg.Tokenize(inmsg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(seq.LongString())
}

func parse(cmd *cobra.Command, args []string) {
	if infile == "" {
		log.Fatal("Invalid input file")
	}

	profile()

	parser := buildParser()

	iscan, ifile := openFile(infile)
	defer ifile.Close()

	ofile := openOutputFile(outfile)
	defer ofile.Close()

	n := 0
	now := time.Now()

	for iscan.Scan() {
		line := iscan.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		n++

		pseq, err := parser.Parse(line)
		if err != nil {
			log.Printf("Error (%s) parsing: %s", err, line)
		} else {
			fmt.Fprintf(ofile, "%s\n%s\n\n", line, pseq.LongString())
		}
	}

	since := time.Since(now)
	log.Printf("Parsed %d messages in %.2f secs, ~ %.2f msgs/sec", n, float64(since)/float64(time.Second), float64(n)/(float64(since)/float64(time.Second)))
	close(quit)
	<-done
}

func bench(cmd *cobra.Command, args []string) {
	if infile == "" {
		log.Fatal("Invalid input file")
	}

	parser := buildParser()

	iscan, ifile := openFile(infile)
	defer ifile.Close()

	var lines []string
	n := 0

	for iscan.Scan() {
		line := iscan.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		n++
		lines = append(lines, line)
	}

	profile()

	now := time.Now()

	msgpipe := make(chan string, 10000)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range msgpipe {
				parser.Parse(line)
			}
		}()
	}

	for _, line := range lines {
		msgpipe <- line
	}
	close(msgpipe)

	wg.Wait()

	since := time.Since(now)
	log.Printf("Parsed %d messages in %.2f secs, ~ %.2f msgs/sec", n, float64(since)/float64(time.Second), float64(n)/(float64(since)/float64(time.Second)))
	close(quit)
	<-done
}

func buildParser() *sequence.Parser {
	parser := sequence.NewParser()

	var files []string

	if patdir != "" {
		files = getDirOfFiles(patdir)
	}

	if patfile != "" {
		files = append(files, patfile)
	}

	for _, file := range files {
		// Open pattern file
		pscan, pfile := openFile(file)

		for pscan.Scan() {
			line := pscan.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			if err := parser.Add(line); err != nil {
				log.Fatal(err)
			}
		}

		pfile.Close()
	}

	return parser
}

func openFile(fname string) (*bufio.Scanner, *os.File) {
	var s *bufio.Scanner

	f, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}

	if strings.HasSuffix(fname, ".gz") {
		gunzip, err := gzip.NewReader(f)
		if err != nil {
			log.Fatal(err)
		}

		s = bufio.NewScanner(gunzip)
	} else {
		s = bufio.NewScanner(f)
	}

	return s, f
}

func getDirOfFiles(path string) []string {
	filenames := make([]string, 0, 10)

	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		filenames = append(filenames, path+"/"+f.Name())
	}

	return filenames
}

func openOutputFile(fname string) *os.File {
	var (
		ofile *os.File
		err   error
	)

	if fname == "" {
		ofile = os.Stdin
	} else {
		// Open output file
		ofile, err = os.OpenFile(fname, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
	}

	return ofile
}

func main() {
	sequenceCmd.Execute()
}
