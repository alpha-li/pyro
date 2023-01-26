package main

import (
	"fmt"
	"os"
	"time"

	"alphameta.io/pyro/pkg/spies/cpuspy"
)

func main() {
	s := cpuspy.NewSession(0, 99, 128)
	if s == nil {
		fmt.Fprintln(os.Stderr, "NewSession Failed!")
		os.Exit(1)
	}

	err := s.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Session Start Failed! Error:%s\n", err.Error())
		os.Exit(1)

	}
	defer s.Stop()

	for {
		time.Sleep(1 * time.Second)
		s.Snapshot(func(name []byte, v uint64, pid uint32) error {
			fmt.Printf("Stack:%s Count:%d\n", string(name), v)
			return nil
		})
	}

	s.Stop()
}
