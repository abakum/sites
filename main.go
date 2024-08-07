/*
git clone github.com/abakum/sites
go get github.com/Trisia/gosysproxy
go get github.com/xlab/closer
go install github.com/tc-hib/go-winres@latest
go-winres init
go get github.com/abakum/embed-encrypt
*/
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Trisia/gosysproxy"
	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:generate go run github.com/abakum/embed-encrypt
//go:generate go run github.com/abakum/version

const (
	ROOT = "SetDefaultBrowser"
	SDB  = ROOT + ".exe"
)

//encrypted:embed SetDefaultBrowser
var Bin encryptedfs.FS

var (
	fns                       map[string]string
	DefaultConnectionSettings []byte
	DcsLen                    = 109
)

func main() {
	var (
		err error
		wg  sync.WaitGroup
		ProxySettings,
		report,
		exeDir,
		_ string
		// ProxyMode   = ""
		key registry.Key
	)
	defer closer.Close()
	ctx, ca := context.WithCancel(context.Background())
	closer.Bind(func() {
		ca()
		if err != nil {
			let.Println(err)
			defer os.Exit(1)
		}
		// key, err = registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\ControlSet001\Services\iphlpsvc`, registry.SET_VALUE)
		// if err == nil {
		// 	PrintOk("Start=2", key.SetDWordValue("Start", 2))
		// 	key.Close()
		// }
		// PrintOk("iphlpsvc", iphlpsvc("start"))

		// key, err = registry.OpenKey(registry.CURRENT_USER,
		// 	`SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`, registry.SET_VALUE)
		// if err == nil {
		// 	PrintOk("Autoconfig=1", key.SetDWordValue("Autoconfig", 1))
		// 	key.Close()
		// }
		PrintOk("gosysproxy", proxy(ProxySettings))

		// key, err = registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Policies\YandexBrowser`, registry.SET_VALUE)
		// if err == nil {
		// 	PrintOk("ProxyMode="+ProxyMode, key.SetStringValue("ProxyMode", ProxyMode))
		// 	key.Close()
		// }
		// PrintOk("SetDefaultBrowser", SetDefaultBrowser())

		wg.Wait()
		pressEnter()
	})

	// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\GroupPolicy\
	// администратор через планировщик устанавливает ХОРОШИЕ значения в реестре

	exeDir, err = os.Executable()
	if err != nil {
		panic(1)
	}
	exeDir = filepath.Dir(exeDir)
	fns, report, err = encryptedfs.Xcopy(Bin, ROOT, exeDir, "")
	if report != "" {
		fmt.Println(report)
	}

	key, err = registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err == nil {
		DefaultConnectionSettings, _, err = key.GetBinaryValue("DefaultConnectionSettings")
		PrintOk(fmt.Sprintf("DefaultConnectionSettings[8]=%d len=%d", DefaultConnectionSettings[8], len(DefaultConnectionSettings)), err)
		if len(DefaultConnectionSettings) == DcsLen && DefaultConnectionSettings[8] != 1 {
			ConnectionSettings := bytes.Clone(DefaultConnectionSettings)
			ConnectionSettings[8] = 1
			PrintOk("ConnectionSettings[8]=1", key.SetBinaryValue("DefaultConnectionSettings", ConnectionSettings))
		}
		key.Close()
	}

	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel`, "Autoconfig", 0, func() { PrintOk("gosysproxy", proxy("")) })
	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyEnable", 0, func() { PrintOk("gosysproxy", proxy("")) })

	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "AutoConfigURL", "", func() { PrintOk("gosysproxy", proxy("")) })

	// go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
	// 	`SYSTEM\ControlSet001\Services\iphlpsvc`, "Start", 4, func() { PrintOk("iphlpsvc", iphlpsvc("stop")) })

	go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxySettingsPerUser", 1, nil)

	key, err = registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Policies\YandexBrowser`, registry.QUERY_VALUE)
	if err == nil {
		// ProxyMode, _, err = key.GetStringValue("ProxyMode")
		// PrintOk("ProxyMode="+ProxyMode, err)
		ProxySettings, _, err = key.GetStringValue("ProxySettings")
		PrintOk("ProxySettings="+ProxySettings, err)
		key.Close()
	}
	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\YandexBrowser`, "ProxyPacUrl", ProxySettings, nil)

	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\YandexBrowser`, "ProxyMode", "pac_script", nil) //direct

	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`, "ScreenSaveActive", "0", nil)

	// go anyWatch(ctx, &wg, registry.CURRENT_USER,
	// 	`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableLockWorkstation", 1, nil)
	go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DisableLockWorkstation", 1, nil)

	go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\Personalization`, "NoLockScreen", 1, nil)

	go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E`, "ACSettingIndex", 0, nil)

	go anyWatch(ctx, &wg, registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`, "ProgId", "ChromeHTML", func() { PrintOk("SetDefaultBrowser", SetDefaultBrowser()) })

	go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", 0, nil)

	go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", 0, nil)

	go anyWatch(ctx, &wg, registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Mozilla\Firefox`, "", nil, nil)

	// go anyWatch(ctx, &wg, registry.CURRENT_USER,
	// 	`SOFTWARE\Classes\VncViewer.Config\DefaultIcon`, "", `C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe,0`, nil)

	// go func() {
	// 	time.Sleep(time.Second * 3) // test notify done
	// 	ca()                        // test try done
	// }()
	closer.Hold()
}

// run SetDefaultBrowser without parameters to list all Browsers on your system http://kolbi.cz/blog/?p=396
func SetDefaultBrowser() (err error) {
	// cwd, err := os.Getwd()
	// if err != nil {
	// 	err = srcError(err)
	// 	return
	// }
	// exe := filepath.Join(cwd, "SetDefaultBrowser", "SetDefaultBrowser.exe")
	sdb := exec.Command(fns[SDB],
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
			if old != value { // || err != nil
				err = k.SetStringValue(key, value)
				if err != nil {
					return false, nil, srcError(err)
				}
				return true, old, nil
			}
			return false, old, nil
		}
	case nil:
		fn = func(k registry.Key) (bool, any, error) {
			err := deleteRegistryKey(k)
			if err != nil {
				return false, nil, srcError(err)
			}
			return true, nil, nil
		}
	default:
		letf.Println("wrong type of val", value)
		return
	}

	wg.Add(1)
	defer wg.Done()

	ltf.Println(path, key)
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
			if val == nil && key != "" {
				path += `\` + key
				key = ""
			}
			// query, compare and set
			k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE|syscall.KEY_NOTIFY|registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				if !strings.Contains(err.Error(), "The system cannot find the file specified.") {
					letf.Println(root, path, err)
				}
				continue // next try after tryAfter
			}
			ok, old, err := fn(k)
			if err != nil {
				let.Println(err)
				k.Close()
				continue // next try after tryAfter
			}
			if ok {
				if val == nil {
					ltf.Printf(`deleted %s\`, path)
				} else {
					ltf.Printf(`%s\%s %v->%v`, path, key, old, val)
				}
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
					if !strings.Contains(err.Error(), "Illegal operation attempted on a registry key that has been marked for deletion.") {
						let.Println(err)
					}
				}
			}
		}
	}
}

func proxy(PAC string) error {
	gosysproxy.SetPAC(PAC)
	gosysproxy.Off()
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.SET_VALUE)
	if err == nil {
		if len(DefaultConnectionSettings) == DcsLen {
			ConnectionSettings := DefaultConnectionSettings[:]
			if PAC == "" {
				ConnectionSettings[8] = 1
			}
			PrintOk(fmt.Sprintf("ConnectionSettings[8]=%d len=%d", ConnectionSettings[8], len(ConnectionSettings)), key.SetBinaryValue("DefaultConnectionSettings", ConnectionSettings))
		}
		key.Close()
	}
	cmd := exec.Command("netsh",
		"winhttp",
		"import",
		"proxy",
		"ie",
	)
	return cmd.Run()
}

func iphlpsvc(s string) error {
	cmd := exec.Command("net",
		s,
		"iphlpsvc",
	)
	return cmd.Run()

}

func deleteRegistryKey(key registry.Key) error {
	const c = 1
	// Find all the value names inside the key and delete them.
	valueNames, err := key.ReadValueNames(c)
	if err != nil && err != io.EOF {
		return err
	}

	for _, valueName := range valueNames {
		ltf.Println("DeleteValue", valueName)
		err = key.DeleteValue(valueName)
		if err != nil && err != io.EOF {
			return err
		}
	}

	// Find the subkeys and delete those recursively.
	subkeyNames, err := key.ReadSubKeyNames(c)
	if err != nil && err != io.EOF {
		return err
	}

	for _, subkeyName := range subkeyNames {
		ltf.Println("deleteRegistryKey", subkeyName)
		subKey, err := registry.OpenKey(key, subkeyName, registry.ALL_ACCESS)
		if err != nil {
			return err
		}

		err = deleteRegistryKey(subKey)
		if err != nil {
			return err
		}
	}

	// Then delete itself.
	return registry.DeleteKey(key, "")
}
