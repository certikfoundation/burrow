package jobs

import (
	"github.com/certikfoundation/burrow/deploy/def"
	"github.com/certikfoundation/burrow/logging"
)

func SetAccountJob(account *def.Account, script *def.Playbook, logger *logging.Logger) (string, error) {
	var result string

	// Set the Account in the Package & Announce
	script.Account = account.Address
	logger.InfoMsg("Setting Account", "account", script.Account)

	// Set result and return
	result = account.Address
	return result, nil
}

func SetValJob(set *def.Set, do *def.DeployArgs, logger *logging.Logger) (string, error) {
	var result string
	logger.InfoMsg("Setting Variable", "result", set.Value)
	result = set.Value
	return result, nil
}
