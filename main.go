package main

import (
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows/registry"
)

const (
	uts   = `c:\Windows\CCM\Logs\UpdateTrustedSites.log`
	acURL = "AutoConfigURL"
	is    = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

func main() {
	var (
		err   error
		ok    bool
		event fsnotify.Event
		k     registry.Key
		s     string
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

	// Add a path.
	err = watcher.Add(filepath.Dir(uts))
	if err != nil {
		err = srcError(err)
		return
	}
	ltf.Println(watcher.WatchList())

	// Start listening for events.
	for {
		select {
		case event, ok = <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) && event.Name == uts {
				ltf.Println("modified", event.Name)
				k, err = registry.OpenKey(registry.CURRENT_USER, is, registry.QUERY_VALUE)
				if err == nil {
					s, _, err = k.GetStringValue(acURL)
					if err == nil {
						ltf.Println(s)
						k.DeleteValue(acURL)
					}
					k.Close()
				}
			}
		case err, ok = <-watcher.Errors:
			if !ok {
				return
			}
			letf.Println(err)
		}
	}
}
