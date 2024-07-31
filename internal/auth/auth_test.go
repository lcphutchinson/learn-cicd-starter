package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

var ErrMalformedHeader = errors.New("malformed authorization header")

func TestGetAPIKey(t *testing.T){
	tests := map[string]struct {
		input		http.Header
		wantString	string
		wantError	error
	}{
		"standard":		{
			input: http.Header{"Authorization": []string{"ApiKey key"}}, 
			wantString: "key", 
			wantError: nil,
		},
		"empty header":		{
			input: http.Header{},
			wantString: "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		"malformed label":	{
			input: http.Header{"Authorization": []string{"apikey key"}},
			wantString: "",
			wantError: ErrMalformedHeader,
		},
		"label leading space":	{
			input: http.Header{"Authorization": []string{" ApiKey key"}},
			wantString: "",
			wantError: ErrMalformedHeader,
		},
		"label trailing space":	{
			input: http.Header{"Authorization": []string{"ApiKey  key"}},
			wantString: "",
			wantError: errors.new("junk error for fail state"),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotString, gotErr := GetAPIKey(tc.input)
			if !reflect.DeepEqual(tc.wantString, gotString) || !reflect.DeepEqual(tc.wantError, gotErr) {
				t.Fatalf("\nexpected\t (%v, %v)\ngot \t\t(%v, %v)\n", 
				tc.wantString, tc.wantError,
				gotString, gotErr)
			}
		})
	}
}
		

