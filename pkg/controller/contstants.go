package controller

type RouteAnnotation string

const (
	URLRewriteAnnotation RouteAnnotation = "virtual-server.f5.com/rewrite-target-url"
)
