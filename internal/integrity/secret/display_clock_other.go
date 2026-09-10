//go:build !windows

package secret

import "time"

func displayNow() time.Time { return time.Now() }
