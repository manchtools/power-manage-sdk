package firewall

import (
	"os"

	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// Filesystem seams. The firewalld backend materialises each rule as a service
// XML file. These package vars default to the real fs helpers (fs gains its own
// injected Runner in a later capability PR) and to os.ReadFile, so unit tests can
// drive ApplyRule/RemoveRule/List without writing under /etc/firewalld.
var (
	writeFileAtomic = fs.WriteFileAtomic
	removeStrict    = fs.RemoveStrict
	readFile        = os.ReadFile
)
