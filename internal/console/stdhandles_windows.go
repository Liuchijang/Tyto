//go:build windows

package console

import (
	"os"

	"golang.org/x/sys/windows"
)

// substituted marks the standard handles that init replaced with NUL, so Ensure
// still treats them as missing and attaches or allocates a real console.
var substituted = map[uint32]bool{}

// modernc.org/libc (pulled in by the SQLite driver) panics "no console" from its
// package init when GetStdHandle returns INVALID_HANDLE_VALUE — which is what a
// remote-exec agent that pipes stdout/stderr but passes no stdin produces. That
// panic fires before main, so console.Ensure is too late; this has to be an init.
//
// It runs before libc's because Go initializes packages in import-path order
// among those whose imports are ready (spec, Go 1.21+): this package imports
// only std and golang.org/x/sys/windows, and "github.com/Liuchijang/Tyto/..."
// sorts before "modernc.org/libc". Do not add an import that reaches libc here.
func init() {
	for _, std := range []struct {
		kind   uint32
		access uint32
		file   **os.File
	}{
		{windows.STD_INPUT_HANDLE, windows.GENERIC_READ, &os.Stdin},
		{windows.STD_OUTPUT_HANDLE, windows.GENERIC_WRITE, &os.Stdout},
		{windows.STD_ERROR_HANDLE, windows.GENERIC_WRITE, &os.Stderr},
	} {
		if handle, err := windows.GetStdHandle(std.kind); err == nil && handle != 0 {
			continue
		}
		nul, err := windows.CreateFile(windows.StringToUTF16Ptr("NUL"), std.access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			continue
		}
		if windows.SetStdHandle(std.kind, nul) != nil {
			windows.CloseHandle(nul)
			continue
		}
		*std.file = os.NewFile(uintptr(nul), "NUL")
		substituted[std.kind] = true
	}
}
