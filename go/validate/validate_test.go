package validate

import (
	"strings"
	"testing"
)

type testStruct struct {
	Name  string `validate:"required"`
	Email string `validate:"required,email"`
	ID    string `validate:"ulid"`
	Count int    `validate:"gte=0,lte=100"`
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
}

func TestStruct_Valid(t *testing.T) {
	v := NewValidator()
	s := testStruct{
		Name:  "test",
		Email: "test@example.com",
		ID:    "01JNXZQK7C93M0F42YVSDHE5DA",
		Count: 50,
	}
	msg, ok := Struct(v, s)
	if !ok {
		t.Errorf("expected valid, got error: %s", msg)
	}
}

func TestStruct_InvalidRequired(t *testing.T) {
	v := NewValidator()
	s := testStruct{Email: "test@example.com"}
	msg, ok := Struct(v, s)
	if ok {
		t.Fatal("expected invalid")
	}
	if !strings.Contains(msg, "name is required") {
		t.Errorf("expected 'name is required', got: %s", msg)
	}
}

func TestStruct_InvalidEmail(t *testing.T) {
	v := NewValidator()
	s := testStruct{Name: "test", Email: "not-an-email"}
	msg, ok := Struct(v, s)
	if ok {
		t.Fatal("expected invalid")
	}
	if !strings.Contains(msg, "email must be a valid email address") {
		t.Errorf("expected email error, got: %s", msg)
	}
}

func TestStruct_InvalidULID(t *testing.T) {
	v := NewValidator()
	s := testStruct{Name: "test", Email: "test@example.com", ID: "not-a-ulid"}
	msg, ok := Struct(v, s)
	if ok {
		t.Fatal("expected invalid")
	}
	if !strings.Contains(msg, "must be a valid ULID") {
		t.Errorf("expected ULID error, got: %s", msg)
	}
}

func TestStruct_EmptyULID(t *testing.T) {
	v := NewValidator()
	s := testStruct{Name: "test", Email: "test@example.com", ID: ""}
	_, ok := Struct(v, s)
	if !ok {
		t.Error("empty ULID should be valid (required handles emptiness)")
	}
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ServerURL", "server_u_r_l"},
		{"Name", "name"},
		{"FirstName", "first_name"},
		{"ID", "i_d"},
		{"", ""},
		{"lowercase", "lowercase"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ToSnakeCase(tt.input)
			if got != tt.want {
				t.Errorf("ToSnakeCase(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
