package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Trisia/gosysproxy"
	"github.com/fsnotify/fsnotify"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows/registry"
)

const (
	darkPath = `SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`
	darkKey  = "Autoconfig"
)

func main() {
	var (
		err     error
		ok      bool
		event   fsnotify.Event
		UATDATA = os.Getenv("UATDATA")
		CCM     = `c:\Windows\CCM`
		// trigger   = `c:\Windows\CCM\Logs\UpdateTrustedSites.log`
		changed = make(chan bool, 10)
	)
	defer closer.Close()
	closer.Bind(func() {
		close(changed)
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
	err = watcher.Add(filepath.Join(CCM, "Logs"))
	if err != nil {
		err = srcError(err)
		return
	}
	ltf.Println(watcher.WatchList())

	// https://gist.github.com/jerblack/1d05bbcebb50ad55c312e4d7cf1bc909
	advapi32, err := syscall.LoadDLL("Advapi32.dll")
	if err != nil {
		err = srcError(err)
		return
	}
	regNotifyChangeKeyValue, err := advapi32.FindProc("RegNotifyChangeKeyValue")
	if err != nil {
		err = srcError(err)
		return
	}
	go func() {
		for {
			k, err := registry.OpenKey(registry.CURRENT_USER, darkPath, syscall.KEY_NOTIFY)
			if err == nil {
				regNotifyChangeKeyValue.Call(uintptr(k), 0, 0x00000001|0x00000004, 0, 0)
				changed <- true
				k.Close()
			} else {
				letf.Println("OpenKey")
			}
			time.Sleep(time.Second)
		}
	}()

	changed <- true
	// Start listening for events.
	for {
		select {
		case _, ok = <-changed:
			if !ok {
				return
			}
			ltf.Println(darkPath)
			fix()
		case event, ok = <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) { //&& event.Name == trigger
				ltf.Println(event.Name)
				fix()
			}
		case err, ok = <-watcher.Errors:
			if !ok {
				return
			}
			letf.Println(err)
		}
	}
}

func fix() {
	if dWordValue(registry.CURRENT_USER,
		darkPath,
		darkKey,
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
