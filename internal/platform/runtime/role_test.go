package runtime

import "testing"

func TestParseRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  Role
	}{
		{"", RoleAll},
		{"server", RoleServer},
		{"WORKER", RoleWorker},
		{" all ", RoleAll},
	}
	for _, test := range tests {
		got, err := ParseRole(test.input)
		if err != nil {
			t.Fatalf("ParseRole(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("ParseRole(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	if _, err := ParseRole("api"); err == nil {
		t.Fatal("ParseRole(api) unexpectedly succeeded")
	}
}

func TestRoleComponents(t *testing.T) {
	t.Parallel()

	if got := RoleServer.Components(); !got.Server || got.Worker {
		t.Fatalf("server components = %+v", got)
	}
	if got := RoleWorker.Components(); got.Server || !got.Worker {
		t.Fatalf("worker components = %+v", got)
	}
	if got := RoleAll.Components(); !got.Server || !got.Worker {
		t.Fatalf("all components = %+v", got)
	}
}
