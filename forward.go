package main

func selectBackend(protocol string) (string, string) {
	switch protocol {
	case "imap":
		return "10.251.65.150", "143"
	case "pop3":
		return "10.251.65.150", "110"
	case "smtp":
		return "10.251.65.150", "25"
	default:
		return "10.251.65.150", "25"
	}
}
