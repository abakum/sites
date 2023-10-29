// go get github.com/Trisia/gosysproxy
// go get github.com/xlab/closer
// go install github.com/tc-hib/go-winres@latest
// go-winres init
// git tag v0.1.2-lw
// git push origin --tags

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Trisia/gosysproxy"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func main() {
	var (
		err error
		wg  sync.WaitGroup
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

	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\GroupPolicy\
	// администратор через планировщик устанавливает ХОРОШИЕ значения в реестре
	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`, "Autoconfig", 0, func() { PrintOk("gosysproxy.Off", gosysproxy.Off()) })
	// go anyWatch(registry.CURRENT_USER,
	// 	`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", 0, func() { PrintOk("gosysproxy.Off", gosysproxy.Off()) })
	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\YandexBrowser`, "ProxyMode", "direct", nil)
	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveActive", "0", nil)
	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableLockWorkstation", 1, nil)

	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`, "ProgId", "ChromeHTML", func() { PrintOk("SetDefaultBrowser", SetDefaultBrowser()) })

	// go func() {
	// 	time.Sleep(time.Second * 3) // test notify done
	// 	ca()                        // test try done
	// }()
	closer.Hold()
}

func SetDefaultBrowser() (err error) {
	cwd, err := os.Getwd()
	if err != nil {
		err = srcError(err)
		return
	}
	exe := filepath.Join(cwd, "SetDefaultBrowser", "SetDefaultBrowser.exe")
	sdb := exec.Command(exe,
		"chrome",
		// "delay=1000",
	)
	// sdb.Dir = filepath.Dir(sdb.Path)
	sdb.Stdout = os.Stdout
	sdb.Stderr = os.Stderr
	lt.Println(cmd("Run", sdb))
	err = sdb.Run()
	return
}

func cmd(s string, c *exec.Cmd) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf(`%s "%s" %s`, s, c.Args[0], strings.Join(c.Args[1:], " "))
}

// watch and restore reg key
// следит за восстанавлением реестра
func anyWatch(ctx context.Context, wg *sync.WaitGroup, root registry.Key,
	path, key string, val any, after func()) {

	const (
		tryAfter = time.Second
	)
	var (
		fn func(k registry.Key) (bool, any, error)
	)

	switch value := val.(type) {
	case int:
		fn = func(k registry.Key) (bool, any, error) {
			old, _, err := k.GetIntegerValue(key)
			if uint32(old) != uint32(value) || err != nil {
				err = k.SetDWordValue(key, uint32(value))
				if err != nil {
					return false, nil, srcError(err)
				}
				return true, old, nil
			}
			return false, old, nil
		}
	case uint32:
		fn = func(k registry.Key) (bool, any, error) {
			old, _, err := k.GetIntegerValue(key)
			if uint32(old) != value || err != nil {
				err = k.SetDWordValue(key, value)
				if err != nil {
					return false, nil, srcError(err)
				}
				return true, old, nil
			}
			return false, old, nil
		}
	case uint64:
		fn = func(k registry.Key) (bool, any, error) {
			old, _, err := k.GetIntegerValue(key)
			if uint64(old) != value || err != nil {
				err = k.SetQWordValue(key, value)
				if err != nil {
					return false, nil, srcError(err)
				}
				return true, old, nil
			}
			return false, old, nil
		}
	case string:
		fn = func(k registry.Key) (bool, any, error) {
			old, _, err := k.GetStringValue(key)
			if old != value || err != nil {
				err = k.SetStringValue(key, value)
				if err != nil {
					return false, nil, srcError(err)
				}
				return true, old, nil
			}
			return false, old, nil
		}
	default:
		letf.Println("wrong type of val")
		return
	}

	wg.Add(1)
	defer wg.Done()

	ltf.Println(key)
	try := make(chan struct{})
	notify := make(chan error)
	for {
		go func() {
			// wait until the cause of the error disappears or until the detected changes in the registry run out
			// ждём пока причина ошибки уйдёт или закончатся обнаруженные изменения в реестре
			time.Sleep(tryAfter)
			try <- struct{}{}
		}()
		select {
		case <-ctx.Done():
			ltf.Println(key, "try done")
			return // done
		case <-try:
			// query, compare and set
			k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE|syscall.KEY_NOTIFY)
			if err != nil {
				letf.Println(err)
				continue // next try after tryAfter
			}
			ok, old, err := fn(k)
			if err != nil {
				let.Println(err)
				k.Close()
				continue // next try after tryAfter
			}
			if ok {
				ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				if after != nil {
					go after()
				}
			}
			// wait for change
			go func() {
				// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue
				// If the specified key is closed, the event is signaled
				// чтоб прервать regNotifyChangeKeyValue надо закрыть k
				notify <- srcError(windows.RegNotifyChangeKeyValue(windows.Handle(k), false, windows.REG_NOTIFY_CHANGE_LAST_SET, 0, false)) //windows.REG_NOTIFY_CHANGE_NAME|
			}()
			select {
			case <-ctx.Done():
				ltf.Println(key, "notify done")
				k.Close() // cancel regNotifyChangeKeyValue
				return    // done
			case err = <-notify:
				k.Close()
				if err != nil {
					let.Println(err)
				}
			}
		}
	}
}
