//go:build windows
// +build windows

package main

const (
	// REG_NOTIFY_CHANGE_NAME notifies the caller if a subkey is added or deleted.
	REG_NOTIFY_CHANGE_NAME uint32 = 0x00000001

	// REG_NOTIFY_CHANGE_ATTRIBUTES notifies the caller of changes to the attributes of the key, such as the security descriptor information.
	REG_NOTIFY_CHANGE_ATTRIBUTES uint32 = 0x00000002

	// REG_NOTIFY_CHANGE_LAST_SET notifies the caller of changes to a value of the key. This can include adding or deleting a value, or changing an existing value.
	REG_NOTIFY_CHANGE_LAST_SET uint32 = 0x00000004

	// REG_NOTIFY_CHANGE_SECURITY notifies the caller of changes to the security descriptor of the key.
	REG_NOTIFY_CHANGE_SECURITY uint32 = 0x00000008

	// REG_NOTIFY_THREAD_AGNOSTIC indicates that the lifetime of the registration must not be tied to the lifetime of the thread issuing the RegNotifyChangeKeyValue call. Note: This flag value is only supported in Windows 8 and later.
	REG_NOTIFY_THREAD_AGNOSTIC uint32 = 0x10000000
)

//sys	regNotifyChangeKeyValue(key windows.Handle, watchSubtree bool, notifyFilter uint32, event windows.Handle, asynchronous bool) (regerrno error) = advapi32.RegNotifyChangeKeyValue
