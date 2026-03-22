package validate

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
)

// NewValidator creates a validator instance with custom rules (ULID) registered.
func NewValidator() *validator.Validate {
	v := validator.New()
	v.RegisterValidation("ulid", validateULID)
	return v
}

// validateULID validates that a string is a valid ULID.
func validateULID(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := ulid.Parse(value)
	return err == nil
}

// Struct validates a struct and returns a formatted error string, or "" if valid.
func Struct(v *validator.Validate, s any) (string, bool) {
	if err := v.Struct(s); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			return FormatValidationErrors(validationErrors), false
		}
		return err.Error(), false
	}
	return "", true
}

// FormatValidationErrors formats validation errors into a human-readable string.
func FormatValidationErrors(errs validator.ValidationErrors) string {
	var messages []string
	for _, e := range errs {
		messages = append(messages, FormatFieldError(e))
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(messages, "; "))
}

// FormatFieldError formats a single field error into a human-readable message.
func FormatFieldError(e validator.FieldError) string {
	field := ToSnakeCase(e.Field())

	switch e.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "ulid":
		return fmt.Sprintf("%s must be a valid ULID", field)
	case "min":
		if e.Kind().String() == "string" {
			return fmt.Sprintf("%s must be at least %s characters", field, e.Param())
		}
		return fmt.Sprintf("%s must be at least %s", field, e.Param())
	case "max":
		if e.Kind().String() == "string" {
			return fmt.Sprintf("%s must be at most %s characters", field, e.Param())
		}
		return fmt.Sprintf("%s must be at most %s", field, e.Param())
	case "gte":
		return fmt.Sprintf("%s must be >= %s", field, e.Param())
	case "lte":
		return fmt.Sprintf("%s must be <= %s", field, e.Param())
	case "ne":
		return fmt.Sprintf("%s must not be %s", field, e.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, e.Param())
	case "startswith":
		return fmt.Sprintf("%s must start with %s", field, e.Param())
	default:
		return fmt.Sprintf("%s failed validation: %s", field, e.Tag())
	}
}

// ToSnakeCase converts a PascalCase or camelCase string to snake_case.
func ToSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			result.WriteRune(r + 32) // Convert to lowercase
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}
