package main

import (
	"context"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Trisia/gosysproxy"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	REG_NOTIFY_CHANGE_NAME     = uintptr(0x00000001)
	REG_NOTIFY_CHANGE_LAST_SET = uintptr(0x00000004)
	regNotifyTO                = time.Second * 3
	tryAfter                   = time.Second
)

func main() {
	var (
		err      error
		advapi32 *syscall.DLL
		wg       sync.WaitGroup
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

	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\GroupPolicy\
	go anyWatch(regNotifyChangeKeyValue, ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`, "Autoconfig", 0, func() { PrintOk("gosysproxy.Off", gosysproxy.Off()) })
	// go anyWatch(regNotifyChangeKeyValue, registry.CURRENT_USER,
	// 	`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", 0, func() { PrintOk("gosysproxy.Off", gosysproxy.Off()) })
	go anyWatch(regNotifyChangeKeyValue, ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\YandexBrowser`, "ProxyMode", "direct", nil)
	go anyWatch(regNotifyChangeKeyValue, ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveActive", "0", nil)
	go anyWatch(regNotifyChangeKeyValue, ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableLockWorkstation", 1, nil)

	// go func() {
	// 	time.Sleep(time.Second * 3) // test cancel async
	// 	ca()                        // test cancel anyWatch
	// }()
	closer.Hold()
}

func anyWatch(regNotifyChangeKeyValue *syscall.Proc, ctx context.Context, wg *sync.WaitGroup, root registry.Key, path, key string, val any, after func()) {
	var fn func(k registry.Key) (bool, error)

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
	default:
		letf.Println("wrong type of val")
		return
	}

	wg.Add(1)
	defer wg.Done()

	ltf.Println(key)
	try := make(chan struct{})
	for {
		go func() {
			time.Sleep(tryAfter)
			try <- struct{}{}
		}()
		select {
		case <-ctx.Done():
			ltf.Println(key, "tryAfter ctx.Done")
			return // done
		case <-try:
			qs, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				letf.Println(err)
				continue // next try after tryAfter
			}
			ok, err := fn(qs)
			qs.Close()
			if err != nil {
				let.Println(err)
				continue // next try after tryAfter
			}
			if ok && after != nil {
				after()
			}
			for {
				select {
				case <-ctx.Done():
					ltf.Println(key, "regNotifyTO ctx.Done")
					return // done
				default:
				}
				n, err := registry.OpenKey(root, path, syscall.KEY_NOTIFY)
				if err != nil {
					letf.Println(err)
					break // next try after tryAfter
				}
				notify := true
				go func() {
					time.Sleep(regNotifyTO)
					notify = false
					n.Close()
				}()
				// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue
				// If the specified key is closed, the event is signaled
				r0, _, err := regNotifyChangeKeyValue.Call(uintptr(n), 0, REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET, 0, 0)
				if notify {
					// key changed
					n.Close()
					break // next try after tryAfter
				}
				// timeout
				if r0 != 0 {
					letf.Println(err)
					break // next try after tryAfter
				}
			}
		}
	}
}

// https://git.zx2c4.com/wireguard-go/tree/tun/wintun/registry/registry_windows.go?id=5ca1218a5c16fb9b5e99b61c0b5758f66087e2e4
func regNotify(regNotifyChangeKeyValue *syscall.Proc, ctx context.Context, k registry.Key, to time.Duration) (bool, error) {
	// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue
	if to == 0 {
		// bloking wait
		r0, _, err := regNotifyChangeKeyValue.Call(uintptr(k), 0, REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET, 0, 0)
		if r0 != 0 {
			return false, srcError(err)
		}
		return false, nil
	}
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return false, srcError(err)
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
				return false, srcError(err)
			}
			// bloking wait with timeout
			s, err := windows.WaitForSingleObject(event, uint32(to.Milliseconds()))
			if err != nil {
				return false, srcError(err)
			}
			if s == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
			return false, nil
		}
	}
}
func regNotify2(regNotifyChangeKeyValue *syscall.Proc, ctx context.Context, root registry.Key, path string, to time.Duration) (bool, error) {
	for {
		select {
		case <-ctx.Done():
			return true, nil
		default:
			k, err := registry.OpenKey(root, path, syscall.KEY_NOTIFY)
			if err != nil {
				return false, srcError(err)
			}
			notify := true
			go func() {
				time.Sleep(to)
				notify = false
				k.Close()
			}()
			// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue
			// If the specified key is closed, the event is signaled
			r0, _, err := regNotifyChangeKeyValue.Call(uintptr(k), 0, REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_LAST_SET, 0, 0)
			if notify {
				k.Close()
				return false, nil
			}
			if r0 != 0 {
				return false, srcError(err)
			}
		}
	}
}
