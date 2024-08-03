package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/rizasgahri/elf_analyzer/analyzer"
)

func main() {
	args := os.Args
	if len(args) < 2 {
		log.Fatal("provide an executable file to dump")
	}

	filename := flag.String("filename", "", "A binaey ELF file.")
	action := flag.String("action", "", "Action to make: {dump|debug}.")
	flag.Parse()
	if *filename == "" || *action == "" {
		fmt.Printf("Usage of ./elf_analyzer:\n" +
			"  -action=\"{dump|debug}\": Action to make.\n" +
			"  -filename=\"file\": A binary ELF file.\n")
		os.Exit(2)
	}

	elf_analyzer := analyzer.NewAnalyzer()

	err := elf_analyzer.ValidateFile(*filename)
	if err != nil {
		os.Exit(2)
	}
	fmt.Printf("Tracing program : \"%s\".\n", *filename)

	fmt.Printf("Action : \"%s\".\n", *action)
	switch *action {
	case "debug":
		os.Exit(elf_analyzer.Init_debug(*filename))
	case "dump":
		os.Exit(elf_analyzer.Dump_elf(*filename))
	}
}
