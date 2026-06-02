# METADATA
# title: CloudFront cache behaviour must not permit unencrypted HTTP
# description: viewer_protocol_policy=allow-all permits unencrypted HTTP connections, exposing data in transit.
#              All cache behaviours must use redirect-to-https or https-only.
# custom:
#   controls:
#     - CC6.7
#   schedule: "0 */6 * * *"

package compliance_framework.cloudfront_require_https_viewer_protocol

violation[{"path_pattern": cb.path_pattern, "viewer_protocol_policy": cb.viewer_protocol_policy}] if {
	cb := input.cache_behaviours[_]
	cb.viewer_protocol_policy == "allow-all"
}

title := "CloudFront cache behaviour must not permit unencrypted HTTP"
description := "viewer_protocol_policy=allow-all permits unencrypted HTTP connections, exposing data in transit. All cache behaviours must use redirect-to-https or https-only."
