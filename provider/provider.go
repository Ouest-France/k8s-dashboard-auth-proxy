package provider

type Provider interface {
	Valid(token string) (err error)
}
