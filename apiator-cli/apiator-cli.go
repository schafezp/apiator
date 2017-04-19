package main

import (
	"fmt"
	"os"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "Apiator"
	app.Usage = "Connect to the Apiator server to easily generate APIs"
	app.Action = func(c *cli.Context) error {
		fmt.Println("Pong")
		return nil
	}
	
	app.Run(os.Args)
}
