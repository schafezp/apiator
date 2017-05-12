package main

import (
	"fmt"
	"reflect"
	"os"
	"bufio"
	"strings"
	"io/ioutil"
	"net/http"
	"net/url"
	"encoding/json"
	"github.com/urfave/cli"
)

type AuthResponse struct {
	token string	`json:"token"`
	expires string	`json:"expires"`
}

type ConnectionData struct {
	host string
	auth AuthResponse
}

var useREPL bool
var connection ConnectionData

func postJSON(where string, jsonString string) (*http.Response, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", where, strings.NewReader(jsonString))
	if (err != nil) {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	return client.Do(req)
}

func checkConenction() bool {
	// in the future, check to see if token expires, etc.
	conn := (connection != ConnectionData{})
	fmt.Println("Connection: ", conn, connection.host)
	return conn
}

func main() {
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
					host := c.Args().First()
					user := c.String("user")
					pass := c.String("pass")
					fmt.Println("host: ", host)
					fmt.Println("user: ", user)
					fmt.Println("pass: ", pass)

					resp, err := http.PostForm(host + "/auth",
						url.Values{"username": {user}, "password": {pass}})

					if (err != nil) {
						fmt.Println("ERR: ", err)
						// connection stays nil
					} else {

						// fmt.Println("RESP: ", reflect.TypeOf(resp))
						// fmt.Println("RESP: ", reflect.TypeOf(resp.Body))
						// fmt.Println("RESP: ", resp.Body)
						// fmt.Println("RESP: ", resp.StatusCode)
						if (resp.StatusCode == 200) {
							
							// accepted
							jsonbytes, err := ioutil.ReadAll(resp.Body)
							if (err != nil) {
								fmt.Println("IOERR:", err)
								return nil
							} else {
								fmt.Println("RESP: ", jsonbytes)
								connection = ConnectionData{host, AuthResponse{}}
								json.Unmarshal(jsonbytes, &connection.auth)
								fmt.Println("Connected to host successfully: ", connection.host)
								fmt.Println("Session expires: ", connection.auth.expires)

							}
						} else {
							fmt.Println("Connection Rejected: ", resp.Body, resp.StatusCode)
							return nil
						}
					}
				}
				
				// always use repl once we connect
				connected := checkConenction()
				if (!activeREPL && connected) {
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
					connected := checkConenction()
					if (!connected) {
						fmt.Println("ERR: Relative path requires connection")
						return nil
					} else {
						where = connection.host + where
					}
				}
				fmt.Println("GET: ", where)
				resp, err := http.Get(where)

				if (err != nil) {
					fmt.Println("ERR: ", err)
				} else {
					fmt.Println("RESP: ", resp)
				}

				return nil
			},
		},
		// endpoints (CRUD)
		{
			Name: "endpoint",
			Aliases: []string{"ep"},
			Usage: "Perform a CRUD operation on an endpoint",
			Action: func(c *cli.Context) error {
				fmt.Println("Invalid command")
				return nil
			},
			Subcommands: []cli.Command{
				{
					Name: "create",
					Aliases: []string{"c"},
					ArgsUsage: "[id]",
					Usage: "Create an endpoint",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Expected one argument.");
						} else {
							epid := c.Args().First()
							fmt.Println("Create endpoint: ", epid)
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s", "document": {"request_types": ["Get"],"indexed": false}}`, 
								epid, connection.auth.token)
							where := connection.host + "/create-endpoint"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
				{
					Name: "delete",
					Aliases: []string{"del", "rm", "remove"},
					ArgsUsage: "[id]",
					Usage: "Delete an endpoint",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Expected one argument.");
						} else {
							epid := c.Args().First()
							fmt.Println("Delete endpoint: ", epid)
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s"}`, 
								epid, connection.auth.token)
							where := connection.host + "/delete-endpoint"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
				{
					Name: "update",
					Aliases: []string{"up"},
					Usage: "Update an endpoint",
					ArgsUsage: "[endpoint] [doc]",
					Action: func(c *cli.Context) error {
						if c.NArg() < 2 {
							fmt.Println("Expected two arguments: [endpoint] [doc]");
						} else {
							epid := c.Args()[0]
							doc := strings.Join(c.Args()[1:], " ")
							fmt.Println("Update Endpoint: ", epid)
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s", "document":%s}`, 
								epid, connection.auth.token, doc)
							where := connection.host + "/update-endpoint"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
				{
					Name: "read",
					Aliases: []string{"r", "get"},
					Usage: "Read an endpoint",
					ArgsUsage: "[id]",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Expected one argument.");
						} else {
							epid := c.Args().First()
							fmt.Println("Read endpoint: ", epid)
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s"}`, 
								epid, connection.auth.token)
							where := connection.host + "/get-endpoint"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
				{
					Name: "authorize",
					Aliases: []string{"au", "auth"},
					ArgsUsage: "[id] [user]",
					Usage: "Authorize a user to access an endpoint",
					Action: func(c *cli.Context) error {
						if c.NArg() != 2 {
							fmt.Println("Expected two arguments: [id] [user]");
						} else {
							epid := c.Args()[0]
							user := c.Args()[1]
							fmt.Println("Auth endpoint: ", epid, user)
							fmt.Println("[NOT IMPL YET]")
						}
						return nil
					},
				},
				{
					Name: "metadata",
					Aliases: []string{"meta", "info"},
					ArgsUsage: "[id]",
					Usage: "Returns metadata for an endpoint",
					Action: func(c *cli.Context) error {
						if c.NArg() != 1 {
							fmt.Println("Expected one argument.");
						} else {
							epid := c.Args().First()
							fmt.Println("metadata for endpoint: ", epid)
							fmt.Println("[NOT IMPL YET]")
						}
						return nil
					},
				},
			},
		},
		// put documents in endpoints
		{
			Name: "document",
			Aliases: []string{"doc"},
			Usage: "Modify documents in endpoints",
			Action: func(c *cli.Context) error {
				fmt.Println("Invalid command")
				return nil
			},
			Subcommands: []cli.Command{
				{
					Name: "insert",
					Aliases: []string{"i"},
					Usage: "Insert document into an endpoint",
					ArgsUsage: "[endpoint] [docid] [doc]",
					Action: func(c *cli.Context) error {
						if c.NArg() < 3 {
							fmt.Println("Expected three arguments: [endpoint] [docid] [doc]");
						} else {
							epid := c.Args()[0]
							docid := c.Args()[1]
							doc := strings.Join(c.Args()[2:], " ")
							fmt.Println("Insert into endpoint: ", epid)
							fmt.Println(doc)
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s", "document": %s, "doc_id": "%s"}`, 
								epid, connection.auth.token, doc, docid)
							where := connection.host + "/insert"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
				{
					Name: "delete",
					Aliases: []string{"del", "rm", "remove"},
					ArgsUsage: "[endpoint] [docid]",
					Usage: "Delete a document in endpoint",
					Action: func(c *cli.Context) error {
						if c.NArg() != 2 {
							fmt.Println("Expected two arguments: [id] [docid]");
						} else {
							epid := c.Args()[0]
							docid := c.Args()[1]
							fmt.Println("Delete (Endpoint, Docid): (", epid, ",", docid, ")")
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s", "doc_id":"%s"}`, 
								epid, connection.auth.token, docid)
							where := connection.host + "/delete"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
				{
					Name: "update",
					Aliases: []string{"up"},
					ArgsUsage: "[endpoint] [docid] [doc]",
					Usage: "Update a doc in an endpoint",
					Action: func(c *cli.Context) error {
						if c.NArg() < 3 {
							fmt.Println("Expected three arguments: [endpoint] [docid] [doc]");
						} else {
							epid := c.Args()[0]
							docid := c.Args()[1]
							doc := strings.Join(c.Args()[2:], " ")
							fmt.Println("Update (Endpoint, Docid): (", epid, ",", docid, ")")
							fmt.Println(doc)
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s", "document": %s, "doc_id": "%s"}`, 
								epid, connection.auth.token, doc, docid)
							where := connection.host + "/update"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
				{
					Name: "read",
					Aliases: []string{"r", "get"},
					Usage: "Read document from an endpoint",
					ArgsUsage: "[endpoint] [docid]",
					Action: func(c *cli.Context) error {
						if c.NArg() != 2 {
							fmt.Println("Expected three arguments: [endpoint] [docid]");
						} else {
							epid := c.Args()[0]
							docid := c.Args()[1]
							fmt.Println("Read Doc: ", epid, docid)
							jsonS := fmt.Sprintf(`{"id":"%s", "token":"%s", "doc_id": "%s"}`, 
								epid, connection.auth.token, docid)
							where := connection.host + "/read"
							resp, err := postJSON(where, jsonS)
							if (err != nil) {
								fmt.Println("ERR:", err)
							} else {
								fmt.Println("RESP:", resp)
							}
						}
						return nil
					},
				},
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

		fmt.Println("Unknown command:", c.Args().First())

		// continue to repl loop if needed
		if (useREPL) {
			c.App.Run([]string{os.Args[0], "repl"})
		}

		return nil
	}
	app.EnableBashCompletion = true
	app.Run(os.Args)
}
