package main

import (
        "fmt"
        "math/rand"
        "os"
        "time"

        "github.com/looky-cloud/boom/tools/sst/cmd"
)

func main() {
        rand.Seed(time.Now().UTC().UnixNano())
        _, err := cmd.Sst.ExecRoot(os.Args[1:])
        if err != nil {
                fmt.Fprintf(os.Stderr, "%s\n", err)
                os.Exit(1)
        }
}
