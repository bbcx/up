package common

import (
	"os"

	"github.com/alexcesaro/log/stdlog"
)

var Logger = stdlog.GetFromFlags()

func Check(err error, message string) {
	if err != nil {
		Logger.Error(message)
		Logger.Error(err)
		os.Exit(1)
	}
}
