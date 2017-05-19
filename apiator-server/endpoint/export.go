package endpoint

type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type EndpointCRUD struct {
	ID    string      `json:"id" binding:"required"`
	Token string      `json:"token" binding:"required"`
	Doc   EndpointDoc `json:"document"`
}

type EndpointDoc struct {
	HTTPRequestTypes []string `json:"request_types"`
	Owner            string   `json:"owner"`
	Indexed          bool     `json:"indexed"`
	Index            string   `json:"index"`
	CreatedAt        string   `json:"created_at"`
}
