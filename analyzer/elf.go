package analyzer

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

type analyzer struct{}

func NewAnalyzer() *analyzer {
	return &analyzer{}
}

func (a analyzer) ValidateFile(filename string) error {
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

func (a analyzer) Init_debug(filename string) int {
	attr := &os.ProcAttr{Sys: &syscall.SysProcAttr{Ptrace: true}}
	if proc, err := os.StartProcess(filename, []string{"/"}, attr); err == nil {
		proc.Wait()
		foo := syscall.PtraceAttach(proc.Pid)
		fmt.Printf("Started New Process: %v.\n", proc.Pid)
		fmt.Printf("PtraceAttach res: %v.\n", foo)
		return 0
	}
	return 2
}

func (a analyzer) Dump_dynstr(file *elf.File) {
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

func (a analyzer) Dump_symbols(file *elf.File) {
	fmt.Printf("Symbols:\n")
	symbols, _ := file.Symbols()
	for _, e := range symbols {
		if !strings.EqualFold(e.Name, "") {
			fmt.Printf("\t%s\n", e.Name)
		}
	}
}

func (a analyzer) Dump_elf(filename string) int {
	file, err := elf.Open(filename)
	if err != nil {
		fmt.Printf("Couldn’t open file : \"%s\" as an ELF.\n", filename)
		return 2
	}
	a.Dump_dynstr(file)
	a.Dump_symbols(file)
	return 0
}
