package utils

import "sync"

// Map applies a function to each element of a slice
func Map[T any, U any](slice []T, fn func(T) U) []U {
	result := make([]U, len(slice))
	for i, v := range slice {
		result[i] = fn(v)
	}
	return result
}

// Filter filters a slice based on a predicate
func Filter[T any](slice []T, predicate func(T) bool) []T {
	var result []T
	for _, v := range slice {
		if predicate(v) {
			result = append(result, v)
		}
	}
	return result
}

// ParallelMap applies a function to each element of a slice in parallel
func ParallelMap[T any, U any](slice []T, fn func(T) U) []U {
	result := make([]U, len(slice))
	var wg sync.WaitGroup

	for i, v := range slice {
		wg.Add(1)
		go func(idx int, val T) {
			defer wg.Done()
			result[idx] = fn(val)
		}(i, v)
	}

	wg.Wait()
	return result
}

// Contains checks if a value exists in a slice
func Contains[T comparable](slice []T, target T) bool {
	for _, v := range slice {
		if v == target {
			return true
		}
	}
	return false
}

// Unique returns a slice with duplicate elements removed
func Unique[T comparable](slice []T) []T {
	seen := make(map[T]bool)
	var result []T

	for _, v := range slice {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}

	return result
}
