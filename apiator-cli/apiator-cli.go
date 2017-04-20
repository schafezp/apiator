package main

import (
	"fmt"
	"os"
	"bufio"
	"strings"
	"net/http"
	"net/url"
	"github.com/urfave/cli"
)

func main() {
	var useREPL bool
	var host string
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
					host = c.Args().First()
					user := c.String("user")
					pass := c.String("pass")
					fmt.Println("host: ", host)
					fmt.Println("user: ", user)
					fmt.Println("pass: ", pass)

					resp, err := http.PostForm(host + "/auth",
						url.Values{"username": {user}, "password": {pass}})

					if (err != nil) {
						fmt.Println("ERR: ", err)
						host = ""
					} else {
						fmt.Println("RESP: ", resp)
					}
				}
				
				// always use repl once we connect
				if (!activeREPL && (host != "")) {
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
				fmt.Println("APIator REPL - Type 'exit' when done")
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
		// GET
		{
			Name: "get",
			Usage: "Performs a GET request at the specified location",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "not-relative",
					Usage: "Don't treat the location as a relative path",
				},
			},
			Action: func(c *cli.Context) error {
				where := c.Args().First()
				if (!c.Bool("not-relative")) {
					where = host + where
				}
				fmt.Println("GET: ", where)
				resp, err := http.Get(where)

				if (err != nil) {
					fmt.Println("ERR: ", err)
					host = ""
				} else {
					fmt.Println("RESP: ", resp)
				}

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
