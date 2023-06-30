package main

import (
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/xlab/closer"
)

const (
	uts = `c:\Windows\CCM\Logs\UpdateTrustedSites.log`
)

func main() {
	var (
		err error
	)
	defer closer.Close()
	closer.Bind(func() {
		if err != nil {
			let.Println(err)
			defer os.Exit(1)
		}
		pressEnter()
	})

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		err = srcError(err)
		return
	}
	closer.Bind(func() {
		watcher.Close()
	})

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				ltf.Println("event:", event)
				if event.Has(fsnotify.Write) {
					ltf.Println("modified file:", event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				letf.Println("error:", err)
			}
		}
	}()

	// Add a path.
	err = watcher.Add(filepath.Dir(uts))
	if err != nil {
		err = srcError(err)
		return
	}

	// Block main goroutine forever.
	closer.Hold()
}
