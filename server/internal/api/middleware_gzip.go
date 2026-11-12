package api

import (
	"compress/gzip"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type gzipResponseWriter struct {
	gin.ResponseWriter
	writer *gzip.Writer
}

func (w gzipResponseWriter) Write(data []byte) (int, error) {
	return w.writer.Write(data)
}

func (w gzipResponseWriter) WriteString(data string) (int, error) {
	return w.writer.Write([]byte(data))
}

func gzipMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !shouldGzip(c) {
			c.Next()
			return
		}

		gz := gzip.NewWriter(c.Writer)
		defer gz.Close()

		c.Header("Content-Encoding", "gzip")
		c.Header("Vary", "Accept-Encoding")
		c.Writer.Header().Del("Content-Length")
		c.Writer = gzipResponseWriter{ResponseWriter: c.Writer, writer: gz}
		c.Next()
	}
}

func shouldGzip(c *gin.Context) bool {
	if c.Request.Method == http.MethodHead {
		return false
	}
	if !strings.Contains(c.GetHeader("Accept-Encoding"), "gzip") {
		return false
	}
	if strings.HasPrefix(c.Request.URL.Path, "/mcp") {
		return false
	}
	if strings.Contains(c.GetHeader("Accept"), "text/event-stream") {
		return false
	}
	if strings.EqualFold(c.GetHeader("Connection"), "upgrade") || c.GetHeader("Upgrade") != "" {
		return false
	}
	// 项目数据导出自身已是 gzip 归档（.argus.json.gz），再包一层会双重压缩。
	// 仅精确匹配 "/api/v1/projects/{id}/export"（中间恰一段），不影响 asset-discovery 的 /export。
	if c.Request.Method == http.MethodGet {
		p := strings.TrimPrefix(c.Request.URL.Path, "/api/v1") // = "/projects/{id}/export"
		rest := strings.TrimPrefix(p, "/projects/")
		if rest != p && strings.HasSuffix(rest, "/export") &&
			strings.Count(strings.TrimSuffix(rest, "/export"), "/") == 0 {
			return false
		}
	}
	return true
}
