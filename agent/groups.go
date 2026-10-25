package agent

// GroupBy preserves source order inside each named scheduling group.
func GroupBy[T any](values []T, key func(T) string) map[string][]T {
	groups := make(map[string][]T)
	for _, value := range values {
		name := key(value)
		groups[name] = append(groups[name], value)
	}
	return groups
}
