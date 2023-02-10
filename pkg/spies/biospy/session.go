package biospy

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"alphameta.io/pyro/pkg/symcache"
	"golang.org/x/sys/unix"

	bpf "github.com/aquasecurity/libbpfgo"
)

//#cgo CFLAGS: -I./bpf/
//#include <linux/types.h>
//#include "biotrace.bpf.h"
import "C"

type Session struct {
	pid             int
	symbolCacheSize int

	symCache *symcache.SymbolCache

	module    *bpf.Module
	mapCounts *bpf.BPFMap
	mapStacks *bpf.BPFMap
	prog      *bpf.BPFProg
	link      *bpf.BPFLink

	modMutex sync.Mutex

	roundNumber int
}

const btf = "should not be used" // canary to detect we got relocations

func NewSession(pid int, symbolCacheSize int) *Session {
	return &Session{
		pid:             pid,
		symbolCacheSize: symbolCacheSize,
	}
}

func (s *Session) Start() error {
	var err error
	if err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		return err
	}

	s.modMutex.Lock()
	defer s.modMutex.Unlock()

	if s.symCache, err = symcache.NewSymbolCache(s.symbolCacheSize); err != nil {
		return err
	}
	args := bpf.NewModuleArgs{BPFObjBuff: biotraceBpf,
		BTFObjPath: btf}
	if s.module, err = bpf.NewModuleFromBufferArgs(args); err != nil {
		return err
	}
	if err = s.module.BPFLoadObject(); err != nil {
		return err
	}
	if s.prog, err = s.module.GetProgram("trace_io_start"); err != nil {
		return err
	}
	if err = s.findMaps(); err != nil {
		return err
	}
	if err = s.initArgs(); err != nil {
		return err
	}
	if err = s.attachPerfEvent(); err != nil {
		return err
	}
	return nil
}

func (s *Session) Snapshot(cb func(name []byte, value uint64, pid uint32) error) error {
	s.modMutex.Lock()
	defer s.modMutex.Unlock()

	s.roundNumber += 1

	keys, values, batch, err := s.getCountsMapValues()
	if err != nil {
		return err
	}

	type sf struct {
		pid    uint32
		count  uint32
		kStack []byte
		uStack []byte
		comm   string
	}
	var sfs []sf
	knownStacks := map[uint32]bool{}
	for i, key := range keys {
		ck := (*C.struct_biotrace_key_t)(unsafe.Pointer(&key[0]))
		value := values[i]

		pid := uint32(ck.pid)
		kStackID := int64(ck.kern_stack)
		uStackID := int64(ck.user_stack)
		count := binary.LittleEndian.Uint32(value)
		var comm string = C.GoString(&ck.comm[0])
		if uStackID >= 0 {
			knownStacks[uint32(uStackID)] = true
		}
		if kStackID >= 0 {
			knownStacks[uint32(kStackID)] = true
		}
		uStack := s.getStack(uStackID)
		kStack := s.getStack(kStackID)
		sfs = append(sfs, sf{pid: pid, uStack: uStack, kStack: kStack, count: count, comm: comm})
	}
	for _, it := range sfs {
		buf := bytes.NewBuffer(nil)
		buf.Write([]byte(it.comm))
		buf.Write([]byte{';'})
		s.walkStack(buf, it.uStack, it.pid, true)
		s.walkStack(buf, it.kStack, 0, false)
		err = cb(buf.Bytes(), uint64(it.count), it.pid)
		if err != nil {
			return err
		}
	}
	if err = s.clearCountsMap(keys, batch); err != nil {
		return err
	}
	if err = s.clearStacksMap(knownStacks); err != nil {
		return err
	}
	return nil
}

func (s *Session) Stop() {
	s.symCache.Clear()
	s.module.Close()
}

func (s *Session) findMaps() error {
	var err error
	if s.mapCounts, err = s.module.GetMap("counts"); err != nil {
		return err
	}
	if s.mapStacks, err = s.module.GetMap("stacks"); err != nil {
		return err
	}
	return nil
}
func (s *Session) initArgs() error {
	return nil
}

func (s *Session) attachPerfEvent() error {
	var err error
	if _, err = s.prog.AttachGeneric(); err != nil {
		return err
	}
	return nil
}

func (s *Session) getStack(stackId int64) []byte {
	if stackId < 0 {
		return nil
	}
	stackIdU32 := uint32(stackId)
	key := unsafe.Pointer(&stackIdU32)
	stack, err := s.mapStacks.GetValue(key)
	if err != nil {
		return nil
	}
	return stack

}
func (s *Session) walkStack(line *bytes.Buffer, stack []byte, pid uint32, userspace bool) {
	if len(stack) == 0 {
		return
	}
	var stackFrames []string
	for i := 0; i < 127; i++ {
		it := stack[i*8 : i*8+8]
		ip := binary.LittleEndian.Uint64(it)
		if ip == 0 {
			break
		}
		sym := s.symCache.Resolve(pid, ip, s.roundNumber)
		if !userspace && sym.Name == "" {
			continue
		}
		name := sym.Name
		if sym.Name == "" {
			if sym.Module != "" {
				name = fmt.Sprintf("%s+0x%x", sym.Module, sym.Offset)
			} else {
				name = "[unknown]"
			}
		}
		stackFrames = append(stackFrames, name+";")
	}
	reverse(stackFrames)
	for _, s := range stackFrames {
		line.Write([]byte(s))
	}
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

//go:embed bpf/biotrace.bpf.o
var biotraceBpf []byte
