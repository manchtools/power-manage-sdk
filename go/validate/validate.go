package validate

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
)

// NewValidator creates a validator instance with custom rules (ULID) registered.
// It panics if a custom validation rule cannot be registered; the only documented
// failure mode is an invalid tag name or nil function, both of which would be a
// programmer error caught at first run rather than a runtime condition.
func NewValidator() *validator.Validate {
	v := validator.New()
	if err := v.RegisterValidation("ulid", validateULID); err != nil {
		panic(fmt.Sprintf("validate: registering ulid validation failed: %v", err))
	}
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
// Handles acronyms correctly: `UserID` → `user_id`, `HTTPStatusCode` →
// `http_status_code`. The previous shape walked uppercase letters one
// at a time, producing `user_i_d` / `h_t_t_p_status_code` — neither
// of those matches any Go-stdlib convention and the result leaks into
// validation error messages users see (#140).
//
// Rule: insert `_` before an uppercase letter at position i > 0 when
// either of the following transitions holds:
//  1. previous char is lowercase  → leaving a word, entering an acronym
//     or a new word: `userID` → `user_ID`, `myValue` → `my_Value`
//  2. previous char is uppercase AND next char is lowercase
//     → end of acronym, start of a new
//     word: `HTTPStatus` → `HTTP_Status`, `userID` keeps `ID` together
//     because `D` has no lowercase next.
//
// Both rules then lowercase the uppercase letter. Digits + non-ASCII
// runes pass through unchanged (they don't trigger transitions).
func ToSnakeCase(s string) string {
	runes := []rune(s)
	var result strings.Builder
	result.Grow(len(s) + 4) // small headroom for inserted underscores
	for i, r := range runes {
		isUpper := r >= 'A' && r <= 'Z'
		if i > 0 && isUpper {
			prev := runes[i-1]
			prevLower := prev >= 'a' && prev <= 'z'
			nextLower := false
			if i+1 < len(runes) {
				next := runes[i+1]
				nextLower = next >= 'a' && next <= 'z'
			}
			prevUpper := prev >= 'A' && prev <= 'Z'
			if prevLower || (prevUpper && nextLower) {
				result.WriteByte('_')
			}
		}
		if isUpper {
			result.WriteRune(r + 32) // ASCII-shift to lowercase
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}
