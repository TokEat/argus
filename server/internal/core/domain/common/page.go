package common

// Page 定义列表查询的统一分页输入。
type Page struct {
	Limit  int
	Offset int
}

func (p Page) Normalize(defaultLimit, maxLimit int) Page {
	if p.Limit <= 0 {
		p.Limit = defaultLimit
	}
	if maxLimit > 0 && p.Limit > maxLimit {
		p.Limit = maxLimit
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}
