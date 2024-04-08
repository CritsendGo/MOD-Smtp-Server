package smtp

import "fmt"

var (
	Smtp_Message_Welcome = "Hello %s"
)

func ResponseNoEhlo() (int, EnhancedCode, string) {
	return 502, EnhancedCode{5, 5, 1}, "Please introduce yourself first."
}
func ResponseBadPipe() (int, EnhancedCode, string) {
	return 502, EnhancedCode{5, 5, 1}, "MAIL not allowed during message transfer"
}
func ResponseWelcome(ehlo string) (int, EnhancedCode, string) {
	out := fmt.Sprintf(Smtp_Message_Welcome, ehlo)
	return 250, EnhancedCode{2, 0, 0}, out
}
