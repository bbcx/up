package slack_test

import (
	"testing"

	"github.com/bbck/up.bootstrap/pkg/slack"
)


func TestSendMessage(t *testing.T ){
	room := "C1YGDBKJR"
	message := "new message"
	if ! (slack.SendMessage(room, message)) {
		t.Error("slack test failed")
	}
}
