package main

import (
	"fmt"

	"github.com/certikfoundation/burrow/project"
)

func main() {
	fmt.Println(project.History.MustChangelog())
}
