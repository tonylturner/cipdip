package handlers

import (
	"context"

	"github.com/tturner/cipdip/internal/cip/protocol"
)

const (
	ClassAny   uint16 = 0xFFFF
	ServiceAny uint8  = 0xFF
)

type Handler interface {
	HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error)
}

type HandlerFunc func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error)

type Registry struct {
	exact      map[handlerKey][]HandlerFunc
	classAny   map[uint16][]HandlerFunc
	serviceAny map[uint8][]HandlerFunc
	any        []HandlerFunc
}

type handlerKey struct {
	class   uint16
	service uint8
}

func NewRegistry() *Registry {
	return &Registry{
		exact:      make(map[handlerKey][]HandlerFunc),
		classAny:   make(map[uint16][]HandlerFunc),
		serviceAny: make(map[uint8][]HandlerFunc),
		any:        nil,
	}
}

func WrapHandler(handler Handler) HandlerFunc {
	return func(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
		resp, err := handler.HandleCIPRequest(ctx, req)
		return resp, true, err
	}
}

func (r *Registry) Register(class uint16, service uint8, handler HandlerFunc) {
	switch {
	case class == ClassAny && service == ServiceAny:
		r.any = append(r.any, handler)
	case class == ClassAny:
		r.serviceAny[service] = append(r.serviceAny[service], handler)
	case service == ServiceAny:
		r.classAny[class] = append(r.classAny[class], handler)
	default:
		key := handlerKey{class: class, service: service}
		r.exact[key] = append(r.exact[key], handler)
	}
}

func (r *Registry) RegisterHandler(class uint16, service uint8, handler Handler) {
	r.Register(class, service, WrapHandler(handler))
}

func (r *Registry) Handle(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
	if r == nil {
		return protocol.CIPResponse{}, false, nil
	}

	key := handlerKey{class: req.Path.Class, service: uint8(req.Service)}
	if handlers, ok := r.exact[key]; ok {
		if resp, handled, err := tryHandlers(ctx, req, handlers); handled || err != nil {
			return resp, handled, err
		}
	}

	if handlers, ok := r.classAny[req.Path.Class]; ok {
		if resp, handled, err := tryHandlers(ctx, req, handlers); handled || err != nil {
			return resp, handled, err
		}
	}

	if handlers, ok := r.serviceAny[uint8(req.Service)]; ok {
		if resp, handled, err := tryHandlers(ctx, req, handlers); handled || err != nil {
			return resp, handled, err
		}
	}

	if resp, handled, err := tryHandlers(ctx, req, r.any); handled || err != nil {
		return resp, handled, err
	}

	return protocol.CIPResponse{}, false, nil
}

func tryHandlers(ctx context.Context, req protocol.CIPRequest, handlers []HandlerFunc) (protocol.CIPResponse, bool, error) {
	for _, handler := range handlers {
		resp, handled, err := handler(ctx, req)
		if handled || err != nil {
			return resp, handled, err
		}
	}
	return protocol.CIPResponse{}, false, nil
}
