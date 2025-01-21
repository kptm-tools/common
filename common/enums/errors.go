package enums

type ErrorCode string

const (
	// ServiceError occurs when a service or dependency is unavailable or fails to respond.
	ToolError ErrorCode = "SERVICE_ERROR"

	// ParsingError occurs when data cannot be parsed or deserialized correctly.
	ParsingError ErrorCode = "PARSING_ERROR"

	// ValidationError occurs when input data fails validation checks.
	ValidationError ErrorCode = "VALIDATION_ERROR"

	// CommunicationError occurs when network communication or event handling fails.
	CommunicationError ErrorCode = "COMMUNICATION_ERROR"

	// TimeoutError occurs when an operation exceeds the allowed time to complete.
	TimeoutError ErrorCode = "TIMEOUT_ERROR"
)
