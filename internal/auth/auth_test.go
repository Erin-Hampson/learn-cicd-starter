package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		expectError bool
		errorIs     error
	}{
		{
			name:        "missing authorization header",
			headers:     http.Header{},
			wantKey:     "",
			expectError: true,
			errorIs:     ErrNoAuthHeaderIncluded,
		},
		{
			name: "wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer xyz"},
			},
			wantKey:     "",
			expectError: true,
		},
		{
			name: "missing key value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:     "",
			expectError: true,
		},
		{
			name: "valid ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret"},
			},
			wantKey:     "my-secret",
			expectError: false,
		},
		{
			name: "extra spaces between scheme and key",
			headers: http.Header{
				"Authorization": []string{"ApiKey   spaced-value"},
			},
			wantKey:     "",
			expectError: false, // GetAPIKey returns empty key and no error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectError && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("did not expect error but got: %v", err)
			}
			if tt.errorIs != nil && err != tt.errorIs {
				t.Fatalf("expected error %v, got %v", tt.errorIs, err)
			}

			if key != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, key)
			}
		})
	}
}
