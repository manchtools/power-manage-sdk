package smart_test

import (
	"context"
	"fmt"
	"log"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/smart"
)

// ExampleNew scans for devices and prints each one's health.
func ExampleNew() {
	r, err := exec.NewRunner(exec.Direct) // smartctl needs root
	if err != nil {
		log.Fatal(err)
	}
	c, err := smart.New(r)
	if err != nil {
		log.Fatal(err)
	}
	devs, err := c.Scan(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, d := range devs {
		info, err := c.Device(context.Background(), d.Name)
		if err != nil {
			continue
		}
		fmt.Printf("%s healthy=%v %d°C\n", info.Name, info.Healthy, info.TemperatureC)
	}
}
