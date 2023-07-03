package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Trisia/gosysproxy"
	"github.com/fsnotify/fsnotify"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	REG_NOTIFY_CHANGE_NAME     = uintptr(0x00000001)
	REG_NOTIFY_CHANGE_LAST_SET = uintptr(0x00000004)
	asyncTO                    = uint32(3000) // 3s
	watchTO                    = time.Second
)

var (
	wg sync.WaitGroup
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
	ctx, ca := context.WithCancel(context.Background())
	closer.Bind(func() {
		ca()
		if err != nil {
			let.Println(err)
			defer os.Exit(1)
		}
		wg.Wait()
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
	go anyWatch(regNotifyChangeKeyValue, ctx, registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`, "Autoconfig", 0, func() { PrintOk("gosysproxy.Off", gosysproxy.Off()) })
	// go anyWatch(regNotifyChangeKeyValue, registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", 0, func() { PrintOk("gosysproxy.Off", gosysproxy.Off()) })
	go anyWatch(regNotifyChangeKeyValue, ctx, registry.CURRENT_USER, `SOFTWARE\Policies\YandexBrowser`, "ProxyMode", "direct", nil)
	go anyWatch(regNotifyChangeKeyValue, ctx, registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveActive", "0", nil)
	go anyWatch(regNotifyChangeKeyValue, ctx, registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableLockWorkstation", 1, nil)

	// go func() {
	// 	time.Sleep(time.Second * 3) // test cancel async
	// 	ca() // test cancel anyWatch
	// }()

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

func anyWatch(regNotifyChangeKeyValue *syscall.Proc, ctx context.Context, root registry.Key, path, key string, val any, after func()) {
	wg.Add(1)
	defer wg.Done()
	fn := func(k registry.Key) (bool, error) {
		return false, Errorf("wrong type of val")
	}
	switch value := val.(type) {
	case int:
		fn = func(k registry.Key) (bool, error) {
			old, _, err := k.GetIntegerValue(key)
			if uint32(old) != uint32(value) || err != nil {
				err = k.SetDWordValue(key, uint32(value))
				if err != nil {
					return false, srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, value)
				return true, nil
			}
			return false, nil
		}
	case uint32:
		fn = func(k registry.Key) (bool, error) {
			old, _, err := k.GetIntegerValue(key)
			if uint32(old) != value || err != nil {
				err = k.SetDWordValue(key, value)
				if err != nil {
					return false, srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, value)
				return true, nil
			}
			return false, nil
		}
	case uint64:
		fn = func(k registry.Key) (bool, error) {
			old, _, err := k.GetIntegerValue(key)
			if uint64(old) != value || err != nil {
				err = k.SetQWordValue(key, value)
				if err != nil {
					return false, srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, value)
				return true, nil
			}
			return false, nil
		}
	case string:
		fn = func(k registry.Key) (bool, error) {
			old, _, err := k.GetStringValue(key)
			if old != value || err != nil {
				err = k.SetStringValue(key, value)
				if err != nil {
					return false, srcError(err)
				}
				ltf.Printf(`%s\%s %v->%v`, path, key, old, value)
				return true, nil
			}
			return false, nil
		}
	}
	for {
		sec := time.NewTimer(watchTO)
		select {
		case <-ctx.Done():
			ltf.Println(key, "ctx.Done")
			return
		case <-sec.C:
			k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE|syscall.KEY_NOTIFY)
			if err != nil {
				letf.Println(err)
				continue
			}
			ok, err := fn(k)
			if err != nil {
				let.Println(err)
				k.Close()
				continue
			}
			if ok && after != nil {
				after()
			}
			// bloking wait
			// regNotifyChangeKeyValue(key windows.Handle, watchSubtree bool, notifyFilter uint32, event windows.Handle, asynchronous bool) (regerrno error)
			// regNotifyChangeKeyValue.Call(uintptr(k), 0, REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET, 0, 0)
			done, err := async(regNotifyChangeKeyValue, ctx, k)
			k.Close()
			if err != nil {
				let.Println(err)
				continue
			}
			if done {
				ltf.Println(key, "async ctx.Done")
				return
			}

		}
	}
}

// https://git.zx2c4.com/wireguard-go/tree/tun/wintun/registry/registry_windows.go?id=5ca1218a5c16fb9b5e99b61c0b5758f66087e2e4
func async(regNotifyChangeKeyValue *syscall.Proc, ctx context.Context, k registry.Key) (bool, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		letf.Println(err)
		return false, err
	}
	defer windows.CloseHandle(event)

	for {
		select {
		case <-ctx.Done():
			return true, nil
		default:
			r0, _, err := regNotifyChangeKeyValue.Call(uintptr(k), 0, REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET, uintptr(windows.Handle(event)), 1)
			// PrintOk(fmt.Sprintf("regNotifyChangeKeyValue %v", r0), err)
			if r0 != 0 {
				letf.Println(err)
				return false, err
			}
			// bloking wait with timeout
			s, err := windows.WaitForSingleObject(event, asyncTO)
			if err != nil {
				letf.Println(err)
				return false, err
			}
			if s == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
			return false, nil
		}
	}
}
