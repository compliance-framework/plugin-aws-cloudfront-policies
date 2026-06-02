package compliance_framework.cloudfront_require_https_viewer_protocol

import rego.v1

# No cache behaviours — no violation
test_no_violation_no_behaviours if {
	count(violation) == 0 with input as {"cache_behaviours": []}
}

# All behaviours use redirect-to-https — no violation
test_no_violation_redirect_to_https if {
	count(violation) == 0 with input as {
		"cache_behaviours": [
			{"path_pattern": "/*", "viewer_protocol_policy": "redirect-to-https"},
			{"path_pattern": "/api/*", "viewer_protocol_policy": "redirect-to-https"},
		],
	}
}

# All behaviours use https-only — no violation
test_no_violation_https_only if {
	count(violation) == 0 with input as {
		"cache_behaviours": [
			{"path_pattern": "/*", "viewer_protocol_policy": "https-only"},
		],
	}
}

# Default behaviour uses allow-all — violation for that behaviour
test_violation_default_behaviour_allow_all if {
	count(violation) == 1 with input as {
		"cache_behaviours": [
			{"path_pattern": "/*", "viewer_protocol_policy": "allow-all"},
			{"path_pattern": "/api/*", "viewer_protocol_policy": "redirect-to-https"},
		],
	}
}

# Multiple behaviours use allow-all — one violation per offending behaviour
test_violation_multiple_allow_all if {
	count(violation) == 2 with input as {
		"cache_behaviours": [
			{"path_pattern": "/*", "viewer_protocol_policy": "allow-all"},
			{"path_pattern": "/static/*", "viewer_protocol_policy": "allow-all"},
			{"path_pattern": "/api/*", "viewer_protocol_policy": "redirect-to-https"},
		],
	}
}

# Violation includes path_pattern and viewer_protocol_policy for traceability
test_violation_contains_path_pattern if {
	v := violation with input as {
		"cache_behaviours": [
			{"path_pattern": "/images/*", "viewer_protocol_policy": "allow-all"},
		],
	}
	count(v) == 1
	v[{"path_pattern": "/images/*", "viewer_protocol_policy": "allow-all"}]
}
