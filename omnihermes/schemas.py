"""Tool schemas for OmniHermes.

These schemas define the tools exposed by OmniHermes to the Hermes LLM runtime.
"""

OMNIHERMES_STATUS_SCHEMA = {
    "name": "omnihermes_status",
    "description": "Check whether the OmniHermes security gate is locked or unlocked, how many seconds remain, and who the enrolled owner is.",
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

OMNIHERMES_ENROLL_SCHEMA = {
    "name": "omnihermes_enroll",
    "description": "Enroll an owner's face for biometric authorization. Captures biometric embeddings locally on-device with zero raw images stored.",
    "parameters": {
        "type": "object",
        "properties": {
            "owner_name": {
                "type": "string",
                "description": "Name of the primary workstation owner to enroll .",
            },
            "primary": {
                "type": "boolean",
                "description": "Whether this user is the primary workstation owner.",
            },
        },
        "required": ["owner_name"],
    },
}

OMNIHERMES_CONFIGURE_SCHEMA = {
    "name": "omnihermes_configure",
    "description": "Update OmniHermes security policy settings, such as guarded tools, mode, and away timeout.",
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
                "description": "'strict' prompts every time; 'cached_presence' allows actions while continuous presence is detected.",
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

OMNIHERMES_UNLOCK_SCHEMA = {
    "name": "omnihermes_unlock",
    "description": (
        "Ask the workstation owner to verify their face at the webcam. On success, high-risk "
        "actions are allowed for the owner's configured unlock window. Takes no arguments."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

# Aliases
PRESENCE_STATUS_SCHEMA = OMNIHERMES_STATUS_SCHEMA
PRESENCE_ENROLL_SCHEMA = OMNIHERMES_ENROLL_SCHEMA
PRESENCE_CONFIGURE_SCHEMA = OMNIHERMES_CONFIGURE_SCHEMA
PRESENCE_AUDIT_LOGS_SCHEMA = OMNIHERMES_AUDIT_LOGS_SCHEMA
PRESENCE_UNLOCK_SCHEMA = OMNIHERMES_UNLOCK_SCHEMA
