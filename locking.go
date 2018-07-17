package prekeyserver

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"strings"
	"time"
)

func hasLocks(dir string, without string) bool {
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		if !f.IsDir() && (f.Name() == ".lock" || strings.HasPrefix(f.Name(), ".lock-")) && f.Name() != without {
			return true
		}

	}
	return false
}

// lock will place a lock file in the named directory
//  if there is already a lock file there, it will wait
//  until it's been removed
func lockDir(dirName string) uint64 {
	token := rand.Uint64()
	lockName := fmt.Sprintf(".lock-%016X", token)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, token)
	lockFile := path.Join(dirName, lockName)
	finalLockFile := path.Join(dirName, ".lock")

	for {
		for hasLocks(dirName, "") {
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		}
		ioutil.WriteFile(lockFile, b, 0600)
		if !hasLocks(dirName, lockName) {
			os.Rename(lockFile, finalLockFile)
			return token
		}
		// Reaching this line with a test would be very laborous and fragile
		// since we would have to fake a race condition from a test
		// It's possible to do, but probably not worth it.
		os.Remove(lockFile)
	}
}

func unlockDir(dirName string, token uint64) {
	b, e := ioutil.ReadFile(path.Join(dirName, ".lock"))
	if e != nil {
		return
	}
	tt := binary.BigEndian.Uint64(b)
	if tt != token {
		return
	}
	os.Remove(path.Join(dirName, ".lock"))
}
