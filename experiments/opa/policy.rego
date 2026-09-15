# BlockGuard permission policy expressed in Rego, for comparison against the
# smart-contract and in-memory backends. The semantics are deliberately
# identical to AgentPermissionRegistry.checkPermission: a flat per-agent,
# per-action allow map with a fail-closed default.
package blockguard.authz

default allow := false

allow if {
	permissions[input.agent_id][input.action] == true
}

permissions := {
	"agent_b": {
		"search_web": true,
		"read_file": true,
		"transfer_money": true,
		"execute_command": false,
		"delete_database": false,
	},
	"agent_c": {
		"search_web": true,
		"read_file": true,
		"transfer_money": false,
		"execute_command": false,
		"delete_database": false,
	},
}
