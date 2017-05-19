package structs

type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type EndpointCRUD struct {
	ID       string      `json:"id" binding:"required"`
	Token    string      `json:"token" binding:"required"`
	DomainID string      `json:"domain_id" binding:"required"`
	Doc      EndpointDoc `json:"document"`
}

type EndpointDoc struct {
	HTTPRequestTypes []string      `json:"request_types"`
	Owner            string        `json:"owner"`
	Indexed          bool          `json:"indexed"`
	Index            string        `json:"index"`
	CreatedAt        string        `json:"created_at"`
	Statistics       StatisticsDoc `json:"statistics"`
}

type StatisticsDoc struct {
	HitCount            int            `json:"hit_count"`
	MissCount           int            `json:"miss_count"`
	HitRate             float32        `json:"hit_rate"`
	LastCommandReceived string         `json:"last_command_received"`
	Permissions         PermissionsDoc `json:"permissions"`
}

type PermissionsDoc struct {
	Read   []string `json:"read"`
	Write  []string `json:"write"`
	Delete []string `json:"delete"`
}

type DataCRUD struct {
	ID       string      `json:"id" binding:"required"`
	DomainID string      `json:"domain_id" binding:"required"`
	Token    string      `json:"token" binding:"required"`
	Doc      interface{} `json:"document"`
	DocID    string      `json:"doc_id"`
}

type UserCRUD struct {
	ID    string  `json:"id"`
	Token string  `json:"token" binding:"required"`
	Doc   UserDoc `json:"document"`
}

type UserDoc struct {
	Domains  []DomainDoc `json:"domains" binding:"required"`
	Password string      `json:"password"`
}

type DomainDoc struct {
	DomainID  string               `json:"domain_id" binding:"required"`
	Owner     bool                 `json:"owner" binding:"required"`
	Endpoints []DomainEndpointsDoc `json:"endpoints" binding:"required"`
}

type DomainEndpointsDoc struct {
	Name        string `json:"name" binding:"required"`
	Permissions int    `json:"permissions" binding:"required"`
}

type DomainCRUD struct {
	Token    string `json:"token" binding:"required"`
	DomainID string `json:"domain_id" binding:"required"`
}

type UserPermissionsDoc struct {
	ID          string `json:"id" binding:"required"`
	Token       string `json:"token" binding:"required"`
	DomainID    string `json:"domain_id" binding:"required"`
	Permissions int    `json:"permissions"`
	Username    string `json:"username" binding:"required"`
}

type TokenDoc struct {
	Token string `json:"token" binding:"required"`
}

type PasswordDoc struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required"`
}
