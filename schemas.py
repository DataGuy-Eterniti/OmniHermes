"""Tool schemas for Omnihermes.

These JSON schemas define the tools exposed by Omnihermes to the Hermes LLM runtime.
"""

OMNIHERMES_STATUS_SCHEMA = {
    "name": "omnihermes_status",
    "description": "Check the status of the Omnihermes biometric security gate, including enrolled profile, presence status, policy configuration, and audit integrity.",
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

OMNIHERMES_ENROLL_SCHEMA = {
    "name": "omnihermes_enroll",
    "description": "Enroll an owner's face for biometric authorization. Captures biometric embedding securely on-device with zero raw images stored.",
    "parameters": {
        "type": "object",
        "properties": {
            "owner_name": {
                "type": "string",
                "description": "Name or handle of the primary owner to enroll (e.g. 'Alice').",
            },
            "passphrase": {
                "type": "string",
                "description": "Optional user passphrase for hardware-bound AES-256 key derivation.",
            },
        },
        "required": ["owner_name"],
    },
}

OMNIHERMES_CONFIGURE_SCHEMA = {
    "name": "omnihermes_configure",
    "description": "Update Omnihermes security policy settings, such as guarded tools, mode, and away timeout.",
    "parameters": {
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "Enable or disable biometric gate enforcement.",
            },
            "mode": {
                "type": "string",
                "enum": ["strict", "cached_presence"],
                "description": "'strict' prompts every time; 'cached_presence' caches approval while continuous presence is detected.",
            },
            "away_timeout_seconds": {
                "type": "integer",
                "description": "Inactivity threshold in seconds before owner is marked AWAY and actions paused.",
            },
            "guarded_tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of tool names that require biometric authorization before execution.",
            },
        },
        "required": [],
    },
}

OMNIHERMES_AUDIT_LOGS_SCHEMA = {
    "name": "omnihermes_audit_logs",
    "description": "Retrieve recent biometric authorization audit logs and verify the cryptographic integrity of the SHA-256 chain.",
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of recent audit records to return (default: 10).",
            },
            "verify_chain": {
                "type": "boolean",
                "description": "If true, mathematically verifies the cryptographic SHA-256 hash chain of all stored logs.",
            },
        },
        "required": [],
    },
}
