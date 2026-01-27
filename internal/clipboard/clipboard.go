package clipboard

type Clipboard interface {
	Get() (string, error)

	Set(content string) error

	Watch(onChange func(newContent string)) error
}

func New() (Clipboard, error) {
	return newClipboard()
}
