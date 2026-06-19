package osquery_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/osquery"
)

// ExampleNew shows the construct-a-handle flow: pick a Runner, build a Querier,
// and query a benign table. The credential-table deny-list and table-name
// validation are enforced inside QueryTable/Query.
func ExampleNew() {
	r, err := exec.NewRunner(exec.Sudo) // the consumer picks the escalation backend
	if err != nil {
		log.Fatal(err)
	}

	q, err := osquery.New(r)
	if errors.Is(err, osquery.ErrNotInstalled) {
		// osquery isn't installed on this host — skip osquery-dependent features.
		return
	}
	if err != nil {
		log.Fatal(err)
	}

	rows, err := q.QueryTable(context.Background(), "os_version")
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range rows {
		fmt.Println(row.Data["name"])
	}
}
