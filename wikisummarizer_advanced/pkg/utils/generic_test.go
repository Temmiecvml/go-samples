package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMap(t *testing.T) {
	t.Parallel()

	input := []int{1, 2, 3, 4, 5}
	expected := []int{2, 4, 6, 8, 10}

	result := Map(input, func(x int) int { return x * 2 })

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("Map() mismatch (-want +got):\n%s", diff)
	}
}

func TestFilter(t *testing.T) {
	t.Parallel()

	input := []int{1, 2, 3, 4, 5, 6}
	expected := []int{2, 4, 6}

	result := Filter(input, func(x int) bool { return x%2 == 0 })

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("Filter() mismatch (-want +got):\n%s", diff)
	}
}

func TestContains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		slice  []int
		target int
		want   bool
	}{
		{"found", []int{1, 2, 3}, 2, true},
		{"not found", []int{1, 2, 3}, 4, false},
		{"empty slice", []int{}, 1, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Contains(tt.slice, tt.target)
			if got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnique(t *testing.T) {
	t.Parallel()

	input := []int{1, 2, 2, 3, 3, 3, 4}
	expected := []int{1, 2, 3, 4}

	result := Unique(input)

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("Unique() mismatch (-want +got):\n%s", diff)
	}
}

func BenchmarkMap(b *testing.B) {
	input := make([]int, 1000)
	for i := range input {
		input[i] = i
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Map(input, func(x int) int { return x * 2 })
	}
}

func BenchmarkParallelMap(b *testing.B) {
	input := make([]int, 1000)
	for i := range input {
		input[i] = i
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParallelMap(input, func(x int) int { return x * 2 })
	}
}
