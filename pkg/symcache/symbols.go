// Package ebpfspy provides integration with Linux eBPF. It is a rough copy of profile.py from BCC tools:
//
//	https://github.com/iovisor/bcc/blob/master/tools/profile.py
package symcache

import "C"
import (
	"fmt"
	"sync"

	"alphameta.io/pyro/pkg/symtab"
	"alphameta.io/pyro/pkg/util/genericlru"
)

type SymbolCacheEntry struct {
	symbolTable symtab.SymbolTable
	roundNumber int
}
type PidKey uint32

type SymbolCache struct {
	pid2Cache *genericlru.GenericLRU[PidKey, SymbolCacheEntry]
	mutex     sync.Mutex
}

func NewSymbolCache(cacheSize int) (*SymbolCache, error) {
	pid2Cache, err := genericlru.NewGenericLRU[PidKey, SymbolCacheEntry](cacheSize, func(pid PidKey, e *SymbolCacheEntry) {
		e.symbolTable.Close()
	})
	if err != nil {
		return nil, err
	}
	return &SymbolCache{
		pid2Cache: pid2Cache,
	}, nil
}

func (sc *SymbolCache) Resolve(pid uint32, addr uint64, roundNumber int) symtab.Symbol {
	e := sc.getOrCreateCacheEntry(PidKey(pid))
	staleCheck := false
	if roundNumber != e.roundNumber {
		e.roundNumber = roundNumber
		staleCheck = true
	}
	return e.symbolTable.Resolve(addr, staleCheck)
}

func (sc *SymbolCache) getOrCreateCacheEntry(pid PidKey) *SymbolCacheEntry {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	if cache, ok := sc.pid2Cache.Get(pid); ok {
		return cache
	}
	var symbolTable symtab.SymbolTable
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	bcc := func() symtab.SymbolTable {
		return symtab.NewBCCSymbolTable(int(pid))
	}
	symbolTable, err := symtab.NewGoSymbolTable(exe, &bcc)
	if err != nil || symbolTable == nil {
		symbolTable = bcc()
	}
	e := &SymbolCacheEntry{symbolTable: symbolTable}
	sc.pid2Cache.Add(pid, e)
	return e
}

func (sc *SymbolCache) Clear() {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	for _, pid := range sc.pid2Cache.Keys() {
		sc.pid2Cache.Remove(pid)
	}
}
