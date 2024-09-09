package sbc

import "regexp"

func validateMid(mid string) bool {
	re := regexp.MustCompile(`u[0-9a-f]{32}`)
	return re.MatchString(mid)
}

func validatePasscode(passcode string) bool {
	re := regexp.MustCompile(`^\d{6}$`)
	return re.MatchString(passcode)
}
