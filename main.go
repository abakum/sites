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

func main() {
	var (
		err      error
		ok       bool
		event    fsnotify.Event
		UATDATA  = os.Getenv("UATDATA")
		CCM      = `c:\Windows\CCM`
		advapi32 *syscall.DLL
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
	regNotifyChangeKeyValue, err := advapi32.FindProc("RegNotifyChangeKeyValue")
	if err != nil {
		err = srcError(err)
		return
	}
	go anyWatch(regNotifyChangeKeyValue, registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`, "Autoconfig", 0, func() { PrintOk("gosysproxy.Off", gosysproxy.Off()) })
	go anyWatch(regNotifyChangeKeyValue, registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveActive", "0", nil)
	go anyWatch(regNotifyChangeKeyValue, registry.CURRENT_USER, `SOFTWARE\Policies\YandexBrowser`, "ProxyMode", "direct", nil)

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

func anyWatch(regNotifyChangeKeyValue *syscall.Proc, root registry.Key, path, key string, val any, after func()) {
	fn := func(k registry.Key, key string, val any) error {
		return Errorf("wrong type of val")
	}
	switch value := val.(type) {
	case int:
		fn = func(k registry.Key, key string, val any) error {
			old, _, err := k.GetIntegerValue(key)
			if uint32(old) != uint32(value) || err != nil {
				err = k.SetDWordValue(key, uint32(value))
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				if after != nil {
					after()
				}
			}
			return nil
		}
	case uint32:
		fn = func(k registry.Key, key string, val any) error {
			old, _, err := k.GetIntegerValue(key)
			if uint32(old) != value || err != nil {
				err = k.SetDWordValue(key, value)
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				if after != nil {
					after()
				}
			}
			return nil
		}
	case uint64:
		fn = func(k registry.Key, key string, val any) error {
			old, _, err := k.GetIntegerValue(key)
			if uint64(old) != value || err != nil {
				err = k.SetQWordValue(key, value)
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				if after != nil {
					after()
				}
			}
			return nil
		}
	case string:
		fn = func(k registry.Key, key string, val any) error {
			old, _, err := k.GetStringValue(key)
			if old != value || err != nil {
				err = k.SetStringValue(key, value)
				if err != nil {
					return srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				if after != nil {
					after()
				}
			}
			return nil
		}
	}
	for {
		time.Sleep(time.Second)
		k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			letf.Println(err)
			continue
		} else {
			err = fn(k, key, val)
			k.Close()
			if err != nil {
				letf.Println(err)
				continue
			}
		}
		k, err = registry.OpenKey(root, path, syscall.KEY_NOTIFY)
		if err != nil {
			letf.Println(err)
		} else {
			regNotifyChangeKeyValue.Call(uintptr(k), 0, 0x00000001|0x00000004, 0, 0)
			k.Close()
		}
	}
}
