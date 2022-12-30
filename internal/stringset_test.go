package internal

import (
	"fmt"
	"reflect"
	"testing"
)

func TestStringSet(t *testing.T) {
	testCases := []struct {
		name        string
		input       []string
		add         string
		remove      string
		contains    string
		expected    []string
		expectedErr error
	}{
		{
			name:     "Add elements",
			input:    []string{},
			add:      "foo",
			contains: "foo",
			expected: []string{"foo"},
		},
		{
			name:     "Add and remove elements",
			input:    []string{"foo"},
			add:      "bar",
			remove:   "foo",
			contains: "bar",
			expected: []string{"bar"},
		},
		{
			name:        "Try to remove non-existent element",
			input:       []string{"foo"},
			remove:      "bar",
			expectedErr: fmt.Errorf("element 'bar' not found in set"),
			expected:    []string{"foo"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStringSetFromSlice(tc.input)
			if tc.add != "" {
				s.Add(tc.add)
			}

			if tc.remove != "" {
				s.Remove(tc.remove)
			}

			if tc.contains != "" {
				if !s.Contains(tc.contains) {
					t.Errorf("Expected set to contain '%s', but it did not", tc.contains)
				}
			}

			slice := s.ToSlice()
			if !reflect.DeepEqual(slice, tc.expected) {
				t.Errorf("Expected slice %v, got %v", tc.expected, slice)
			}
		})
	}
}
