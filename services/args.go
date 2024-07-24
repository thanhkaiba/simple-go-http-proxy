package services

// tcp := app.Command("tcp", "proxy on tcp mode")
// t := tcp.Flag("tcp-timeout", "tcp timeout milliseconds when connect to real server or parent proxy").Default("2000").Int()

type HTTPArgs struct {
	Parent      string
	Local       string
	HTTPTimeout int
	Interval    int
	Direct      string

	ParentType          string
	LocalType           string
	Timeout             int
	CheckParentInterval int
}
