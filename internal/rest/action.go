package rest

import "strings"

const (
        ActionDrop uint32 = 1 // XDP_DROP
        ActionPass uint32 = 2 // XDP_PASS
)

var actionToString = map[uint32]string{
        ActionDrop: "DROP",
        ActionPass: "PASS",
}

var stringToAction = map[string]uint32{
        "DROP": ActionDrop,
        "PASS": ActionPass,
}

func ActionToString(a uint32) string {
        if s, ok := actionToString[a]; ok {
                return s
        }
        return "UNKNOWN"
}

func ParseAction(s string) (uint32, bool) {
        a, ok := stringToAction[strings.ToUpper(s)]
        return a, ok
}

func ValidAction(a uint32) bool {
        return a == ActionDrop || a == ActionPass
}

