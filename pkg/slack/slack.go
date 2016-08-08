package slack

import (
	"github.com/bbck/up.bootstrap/pkg/common"

	nlopesSlack "github.com/nlopes/slack"
)


var api = nlopesSlack.New("xoxb-66552711254-UsRXrOXKnIZvL2DHDBcePD7h")


func SendMessage(room, message string) bool {
	params := nlopesSlack.PostMessageParameters{}
	channelID, timestamp, err := api.PostMessage(room, message, params)
	common.Check(err, "could not send slack")
	common.Logger.Info("Message successfully sent to channel %s at %s", channelID, timestamp)
	return true
}
