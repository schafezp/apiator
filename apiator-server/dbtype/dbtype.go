package dbtype
type dbtype int

const (
	CouchBase dbtype = iota
	Redis
	Solr
)


type Dbtype interface {
    Dbtype() dbtype
}

// every dbtype must fullfill the Dbtype interface
func(db dbtype) Dbtype() dbtype {
    return db
}


func(db dbtype) OtherMethod()  {
}
