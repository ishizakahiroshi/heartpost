// Package audit defines portable audit event records.
package audit

type Event struct {
	Time     string            `json:"time"`
	Event    string            `json:"event"`
	User     string            `json:"user"`
	Role     string            `json:"role,omitempty"`
	IP       string            `json:"ip,omitempty"`
	Method   string            `json:"method,omitempty"`
	Path     string            `json:"path,omitempty"`
	Query    string            `json:"query,omitempty"`
	Result   string            `json:"result"`
	Message  string            `json:"message,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}
