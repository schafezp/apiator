package main

import (
	"fmt"
	"gopkg.in/couchbase/gocb.v1"
)

func main() {
	cluster, _ := gocb.Connect("couchbase://localhost")
	bucket, _ := cluster.OpenBucket("default", "")
}
