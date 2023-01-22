package symtab

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestGoSymBccFallback(t *testing.T) {
	fmt.Print("---------------------------------1\n")
	bcc := func() SymbolTable {
		return NewBCCSymbolTable(os.Getpid())
	}
	fmt.Print("---------------------------------2\n")
	gosym, _ := NewGoSymbolTable("/proc/self/exe", &bcc)
	fmt.Print("---------------------------------3\n")
	malloc := testHelperGetMalloc()
	fmt.Print("---------------------------------4\n")
	res := gosym.Resolve(uint64(malloc), false)
	fmt.Print("---------------------------------5\n")
	fmt.Printf("||||||||||||||||||%v+", res)
	if !strings.Contains(res.Name, "malloc") {
		t.FailNow()
	}
	if !strings.Contains(res.Module, "libc.so") {
		t.FailNow()
	}
}
func BenchmarkBCC(b *testing.B) {
	gosym, _ := NewGoSymbolTable("/proc/self/exe", nil)
	bccsym := NewBCCSymbolTable(os.Getpid())
	if len(gosym.tab.symbols) < 1000 {
		b.FailNow()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, symbol := range gosym.tab.symbols {
			bccsym.Resolve(symbol.Entry, false)
		}
	}
}
