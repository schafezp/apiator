package main

import (
	"fmt"
	"os"
	"bufio"
	"strings"
	"github.com/urfave/cli"
)

func main() {
	var useREPL bool
	activeREPL := false
	reader := bufio.NewReader(os.Stdin)
	app := cli.NewApp()
	app.Name = "Apiator"
	app.Usage = "Connect to the Apiator server to easily generate APIs"
	app.Flags = []cli.Flag{
		// tells us to use repl or not. set automatically if connect or repl is called
		cli.BoolFlag{
			Name: "use-repl",
			Usage: "If this flag is set to true, the cli will run the REPL after executing the command",
			Destination: &useREPL,
		},
	}
	app.Commands = []cli.Command{
		// command to connect to the db
		{
			Name: "connect",
			Aliases: []string{"c"},
			Usage: "Connect to a apiator server",
			ArgsUsage: "[host]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "user, u",
					Usage: "Username to log-in with",
				},
				cli.StringFlag{
					Name: "pass, p",
					Usage: "Password to log-in with",
				},
			},
			Action: func(c *cli.Context) error {
				if c.NArg() != 1 {
					fmt.Printf("Expected a host argument.");
				} else {
					// print info for debugging
					fmt.Println("host: ", c.Args().First());
					fmt.Println("user: ", c.String("user"));
					fmt.Println("pass: ", c.String("pass"));
				}
				
				// always use repl once we connect
				useREPL = true
				if (!activeREPL) {
					c.App.Run([]string{os.Args[0], "repl"})
				}
				return nil
			},
		},
		// start the repl
		{
			Name: "repl",
			Usage: "Start the REPL",
			Action: func(c *cli.Context) error {
				// make sure we can tell that a repl is active, and we don't start another one
				if activeREPL {
					fmt.Println("Already inside a repl.");
					return nil
				}
				activeREPL = true

				// REPL
				fmt.Println("APIator REPL: Type 'exit' when done")
				cont := true
				for (cont) {
					fmt.Print(">>> ");
					text, _ := reader.ReadString('\n');
					text = strings.TrimSpace(text);
					replargs := strings.Split(text, " ");
					cont = (text != "exit");
					if cont {
						c.App.Run(append([]string{os.Args[0]}, replargs...))
					}
				}

				// done
				activeREPL = false;
				return nil
			},
		},
		// more commands coming soon™
	}
	app.Action = func(c *cli.Context) error {
		// if no args provided, assume they want to use the REPL (for now)
		if c.NArg() == 0 {
			c.App.Run([]string{os.Args[0], "repl"})
			return nil
		}

		fmt.Println("Unkown command:", c.Args().First())

		// continue to repl loop if needed
		if (useREPL) {
			c.App.Run([]string{os.Args[0], "repl"})
		}

		return nil
	}
	
	app.Run(os.Args)
}
