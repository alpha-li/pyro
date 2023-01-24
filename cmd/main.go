package main

import (
	"fmt"
	"os"

	"alphameta.io/pyro/pkg/symcache"
	"github.com/fatih/color"
)

func main() {
	sc, err := symcache.NewSymbolCache(128)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v", color.RedString("Error:"), err)
	}

	sc.Clear()
}
