package runtime

import (
	"fmt"
	"strings"
)

type Role string

const (
	RoleServer Role = "server"
	RoleWorker Role = "worker"
	RoleAll    Role = "all"
)

type ComponentSet struct {
	Server bool
	Worker bool
}

func ParseRole(value string) (Role, error) {
	switch Role(strings.ToLower(strings.TrimSpace(value))) {
	case "", RoleAll:
		return RoleAll, nil
	case RoleServer:
		return RoleServer, nil
	case RoleWorker:
		return RoleWorker, nil
	default:
		return "", fmt.Errorf("APP_ROLE must be server, worker, or all")
	}
}

func (r Role) Components() ComponentSet {
	switch r {
	case RoleServer:
		return ComponentSet{Server: true}
	case RoleWorker:
		return ComponentSet{Worker: true}
	case RoleAll:
		return ComponentSet{Server: true, Worker: true}
	default:
		return ComponentSet{}
	}
}
