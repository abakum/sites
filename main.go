package main

import (
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

var (
	regNotifyChangeKeyValue *syscall.Proc
)

func main() {
	var (
		err     error
		ok      bool
		event   fsnotify.Event
		UATDATA = os.Getenv("UATDATA")
		CCM     = `c:\Windows\CCM`
		// trigger   = `c:\Windows\CCM\Logs\UpdateTrustedSites.log`
		advapi32 *syscall.DLL
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
	advapi32, err = syscall.LoadDLL("Advapi32.dll")
	if err != nil {
		err = srcError(err)
		return
	}
	regNotifyChangeKeyValue, err = advapi32.FindProc("RegNotifyChangeKeyValue")
	if err != nil {
		err = srcError(err)
		return
	}
	go anyWatch(registry.CURRENT_USER, darkPath, darkKey, 0)
	go anyWatch(registry.CURRENT_USER, `SOFTWARE\Policies\YandexBrowser`, "ProxyMode", "direct")

	// Start listening for events.
	for {
		select {
		case event, ok = <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				ltf.Println(event.Name)
			}
		case err, ok = <-watcher.Errors:
			if !ok {
				return
			}
			letf.Println(err)
		}
	}
}

func anyWatch(root registry.Key, path, key string, val any) {
	fn := func(root registry.Key, path, key string, val any) error {
		return Errorf("wrong type of val")
	}
	switch value := val.(type) {
	case int:
		fn = func(root registry.Key, path, key string, val any) error {
			k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				return srcError(err)
			}
			defer k.Close()
			old, _, err := k.GetIntegerValue(key)
			if err != nil {
				return srcError(err)
			}
			if uint32(old) != uint32(value) {
				err = k.SetDWordValue(key, uint32(value))
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				PrintOk("gosysproxy.Off", gosysproxy.Off())
			}
			return nil
		}
	case uint32:
		fn = func(root registry.Key, path, key string, val any) error {
			k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				return srcError(err)
			}
			defer k.Close()
			old, _, err := k.GetIntegerValue(key)
			if err != nil {
				return srcError(err)
			}
			if uint32(old) != value {
				err = k.SetDWordValue(key, value)
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				PrintOk("gosysproxy.Off", gosysproxy.Off())
			}
			return nil
		}
	case uint64:
		fn = func(root registry.Key, path, key string, val any) error {
			k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				return srcError(err)
			}
			defer k.Close()
			old, _, err := k.GetIntegerValue(key)
			if err != nil {
				return srcError(err)
			}
			if uint64(old) != value {
				err = k.SetQWordValue(key, value)
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				PrintOk("gosysproxy.Off", gosysproxy.Off())
			}
			return nil
		}
	case string:
		fn = func(root registry.Key, path, key string, val any) error {
			k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				return srcError(err)
			}
			defer k.Close()
			old, _, err := k.GetStringValue(key)
			if err != nil {
				return srcError(err)
			}
			if old != value {
				err = k.SetStringValue(key, value)
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				PrintOk("gosysproxy.Off", gosysproxy.Off())
			}
			return nil
		}
	}
	for {
		PrintOk(key, fn(root, path, key, val))
		k, err := registry.OpenKey(root, path, syscall.KEY_NOTIFY)
		err = srcError(err)
		if err == nil {
			regNotifyChangeKeyValue.Call(uintptr(k), 0, 0x00000001|0x00000004, 0, 0)
			err = srcError(k.Close())
		}
		if err != nil {
			let.Println(err)
			time.Sleep(time.Second)
		}
	}
}
