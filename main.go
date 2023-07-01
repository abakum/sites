package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Trisia/gosysproxy"
	"github.com/fsnotify/fsnotify"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows/registry"
)

func main() {
	var (
		err     error
		ok      bool
		event   fsnotify.Event
		UATDATA = os.Getenv("UATDATA")
		CCM     = `c:\Windows\CCM`
		// trigger   = `c:\Windows\CCM\Logs\UpdateTrustedSites.log`
		trigger = `trigger.log`
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
	if UATDATA != "" {
		CCM = filepath.Dir(UATDATA)
		CCM = filepath.Dir(CCM)
	}
	logs := filepath.Join(CCM, "Logs")
	err = watcher.Add(logs)
	if err != nil {
		err = srcError(err)
		return
	}
	ltf.Println(watcher.WatchList())

	go func() {
		fn := filepath.Join(logs, trigger)
		if os.WriteFile(fn, []byte{'\n'}, 0644) != nil {
			return
		}
		os.Remove(fn)
	}()

	// Start listening for events.
	for {
		select {
		case event, ok = <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) { //&& event.Name == trigger
				ltf.Println(event.Name)
				if dWordValue(registry.CURRENT_USER,
					`SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`,
					"Autoconfig",
					0,
				) || stringValue(registry.CURRENT_USER,
					`Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
					"AutoConfigURL",
					"",
				) || stringValue(registry.CURRENT_USER,
					`SOFTWARE\Policies\YandexBrowser`,
					"ProxyMode",
					"direct",
				) {
					PrintOk("gosysproxy.Off", gosysproxy.Off())
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

func stringValue(root registry.Key, path, key, val string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err == nil {
		defer k.Close()
		old, _, err := k.GetStringValue(key)
		if err == nil && old != val {
			err = k.SetStringValue(key, val)
			PrintOk(fmt.Sprintf("%s-%s-%v->%v", path, key, old, val), err)
			return err == nil
		}
	}
	return false
}

func dWordValue(root registry.Key, path, key string, val uint32) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err == nil {
		defer k.Close()
		old, _, err := k.GetIntegerValue(key)
		if err == nil && uint32(old) != val {
			err = k.SetDWordValue(key, val)
			PrintOk(fmt.Sprintf("%s-%s-%v->%v", path, key, old, val), err)
			return err == nil
		}
	}
	return false
}
