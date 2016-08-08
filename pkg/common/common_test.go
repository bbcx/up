package common_test

import (
	"testing"

	"github.com/bbck/up.bootstrap/pkg/common"
)


func TestMain(t *testing.T ){
	log := common.Logger
	log.Info("yey")
	log.Debug("debug")
}
