// +build windows

package bcgo

import (
	"os/user"
	"path/filepath"
)

func GetRootDirectoryForUser(u *user.User) string {
	return filepath.Join(u.HomeDir, "AppData", "Roaming", "bc")
}
