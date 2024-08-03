package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
)

func validateFile(filename string) error {
	if len(filename) == 0 {
		return errors.New("the file name cannot be empty")
	}
	file, err := os.Stat(filename)
	if os.IsNotExist(err) {
		fmt.Printf("No such file or directory: %s.\n", filename)
		return err
	} else if mode := file.Mode(); mode.IsDir() {
		fmt.Println("Parameter must be a file, not a directory.")
		return err
	}
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Couldn’t open file: \"%s\".\n", filename)
		return err
	}
	f.Close()

	return nil
}

func init_debug(filename string) int {
	attr := &os.ProcAttr{ Sys: &syscall.SysProcAttr{ Ptrace: true } }
	if proc, err := os.StartProcess(filename, []string { "/" }, attr); err == nil {
		proc.Wait()
		foo := syscall.PtraceAttach(proc.Pid)
		fmt.Printf("Started New Process: %v.\n", proc.Pid)
		fmt.Printf("PtraceAttach res: %v.\n", foo)
		return 0
	}
	return 2;
}

func dump_dynstr(file *elf.File) {
	fmt.Printf("DynStrings:\n")
	dynstrs, _ := file.DynString(elf.DT_NEEDED)
	for _, e := range dynstrs {
		fmt.Printf("\t%s\n", e)
	}
	dynstrs, _ = file.DynString(elf.DT_SONAME)
	for _, e := range dynstrs {
		fmt.Printf("\t%s\n", e)
	}
	dynstrs, _ = file.DynString(elf.DT_RPATH)
	for _, e := range dynstrs {
		fmt.Printf("\t%s\n", e)
	}
	dynstrs, _ = file.DynString(elf.DT_RUNPATH)
	for _, e := range dynstrs {
		fmt.Printf("\t%s\n", e)
	}
}

func dump_symbols(file *elf.File) {
	fmt.Printf("Symbols:\n")
	symbols, _ := file.Symbols()
	for _, e := range symbols {
		if !strings.EqualFold(e.Name, "") {
			fmt.Printf("\t%s\n", e.Name)
		}
	}
}

func dump_elf(filename string) int {
	file, err := elf.Open(filename)
	if err != nil {
		fmt.Printf("Couldn’t open file : \"%s\" as an ELF.\n", filename)
		return 2
	}
	dump_dynstr(file)
	dump_symbols(file)
	return 0
}


func main() {
	args := os.Args
	if len(args) < 2 {
		log.Fatal("provide an executable file to dump")
	}

	filename := flag.String("filename", "", "A binaey ELF file.")
	action := flag.String("action", "", "Action to make: {dump|debug}.")
	flag.Parse()
	if *filename == "" || *action == "" {
		fmt.Printf("Usage of ./main:\n" +
			"  -action=\"{dump|debug}\": Action to make.\n" +
			"  -filename=\"file\": A binary ELF file.\n")
		os.Exit(2)
	}

	err := validateFile(*filename)
	if err != nil {
		os.Exit(2)
	}
	fmt.Printf("Tracing program : \"%s\".\n", *filename)

	fmt.Printf("Action : \"%s\".\n", *action)
	switch *action {
	case "debug":
		os.Exit(init_debug(*filename))
	case "dump":
		os.Exit(dump_elf(*filename))
	}
}
