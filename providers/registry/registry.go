package registry

import (
	"fmt"
	"sort"
	"sync"
)

type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

func New() *Registry {
	return &Registry{adapters: map[string]Adapter{}}
}

func (r *Registry) Register(a Adapter) error {
	d := a.Describe()
	if d.Name == "" || d.AdapterVersion == "" {
		return fmt.Errorf("registry: adapter must declare name and version")
	}
	if len(d.Capabilities) == 0 {
		return fmt.Errorf("registry: adapter %s declares no capabilities", d.Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.adapters[d.Name]; exists {
		return fmt.Errorf("registry: provider %s already registered", d.Name)
	}
	r.adapters[d.Name] = a
	return nil
}

func (r *Registry) Get(name string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	return a, ok
}

func (r *Registry) For(c Capability) []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Adapter
	for _, a := range r.adapters {
		if a.Describe().Supports(c) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Describe().Name < out[j].Describe().Name })
	return out
}

func (r *Registry) Descriptors() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Descriptor
	for _, a := range r.adapters {
		out = append(out, a.Describe())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
