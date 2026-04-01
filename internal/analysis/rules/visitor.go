package rules

import (
	"reflect"
)

// Walk traverses the AST defensively.
func Walk(node interface{}, v func(interface{}) bool) {
	if node == nil {
		return
	}
	// Protect against panic if we recurse into a weird field
	defer func() {
		recover()
	}()

	if !v(node) {
		return
	}

	val := reflect.ValueOf(node)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)

		if !field.IsValid() {
			continue
		}

		switch field.Kind() {
		case reflect.Interface, reflect.Ptr:
			if !field.IsNil() && field.CanInterface() {
				Walk(field.Interface(), v)
			}
		case reflect.Slice:
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				if elem.IsValid() && (elem.Kind() == reflect.Interface || elem.Kind() == reflect.Ptr) {
					if !elem.IsNil() && elem.CanInterface() {
						Walk(elem.Interface(), v)
					}
				}
			}
		}
	}
}
