package recursor

// Ready implements the ready.Readiness interface, once this flips to true CoreDNS
// assumes this plugin is ready for queries; it is not checked again.
func (r recursor) Ready() bool { return len(r.aliases) > 0 }
