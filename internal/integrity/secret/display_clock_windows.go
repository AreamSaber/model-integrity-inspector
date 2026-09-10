package secret

import (
	"time"

	"golang.org/x/sys/windows"
)

// PostgreSQL on Windows reads this precise UTC source. The Go runtime's
// shared-data wall clock may lag it within a tick. Use the precise source here
// without adding skew tolerance or changing the authenticated validity window.
func displayNow() time.Time {
	var ft windows.Filetime
	windows.GetSystemTimePreciseAsFileTime(&ft)
	return time.Unix(0, ft.Nanoseconds()).UTC()
}
