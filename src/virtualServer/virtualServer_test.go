package virtualServer

import (
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
)

func TestConfigFilename(t *testing.T) {
	assert := assert.New(t)

	pid := os.Getpid()
	expectedFilename := "/tmp/f5-k8s-controller.config." + strconv.Itoa(pid) + ".json"

	assert.Equal(expectedFilename, OutputFilename)
}

// FIXME: Add more unit tests
