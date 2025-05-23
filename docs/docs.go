// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "http://swagger.io/terms/",
        "contact": {
            "name": "API Support",
            "url": "http://www.swagger.io/support",
            "email": "support@swagger.io"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/v1/advanced-scan/repo": {
            "post": {
                "description": "Enqueues an advanced scan task for a given repository URL and language.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "scan"
                ],
                "summary": "Trigger a code scan on a repository with advanced scans.",
                "parameters": [
                    {
                        "description": "Request body containing repository URL and language",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.ScanRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successfully enqueued task",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request parameters",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Failed to enqueue scan task",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/reports/owasp/{task_id}": {
            "get": {
                "description": "Generates OWASP report from a specific task result using task ID.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "report"
                ],
                "summary": "Get OWASP report for a task result.",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Task ID",
                        "name": "task_id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successfully generated OWASP report",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/utils.ReportItem"
                            }
                        }
                    },
                    "404": {
                        "description": "Task result not found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Failed to fetch task result",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/reports/sans/{task_id}": {
            "get": {
                "description": "Generates SANS report from a specific task result using task ID.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "report"
                ],
                "summary": "Get SANS report for a task result.",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Task ID",
                        "name": "task_id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successfully generated SANS report",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/utils.SANSReportItem"
                            }
                        }
                    },
                    "404": {
                        "description": "Task result not found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Failed to fetch task result",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/scan/file": {
            "post": {
                "description": "Enqueues a scan task for a given file.",
                "consumes": [
                    "multipart/form-data"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "scan"
                ],
                "summary": "Trigger a code scan on file.",
                "parameters": [
                    {
                        "type": "file",
                        "description": "File to be scanned",
                        "name": "file",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "202": {
                        "description": "Successfully enqueued task",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "No file part or no selected file",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Failed to create temp directory or Failed to save file",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/scan/local": {
            "post": {
                "description": "Enqueues a scan task for a given local repository path and language.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "scan"
                ],
                "summary": "Trigger a code scan on a local repository.",
                "parameters": [
                    {
                        "description": "Request body containing local path and language",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.LocalScanRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successfully enqueued task",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request parameters",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Failed to enqueue scan task",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/scan/repo": {
            "post": {
                "description": "Enqueues a scan task for a given repository URL and language.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "scan"
                ],
                "summary": "Trigger a code scan on a repository.",
                "parameters": [
                    {
                        "description": "Request body containing repository URL and language",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.ScanRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successfully enqueued task",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request parameters",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Failed to enqueue scan task",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/status/{task_id}": {
            "get": {
                "description": "Get the status and results of a scan task by its ID.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "scan"
                ],
                "summary": "Get task status and results.",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Task ID",
                        "name": "task_id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successfully retrieved task result",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "api.LocalScanRequest": {
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "example": "go"
                },
                "local_path": {
                    "type": "string",
                    "example": "/path/to/local/repo"
                }
            }
        },
        "api.ScanRequest": {
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "example": "go"
                },
                "repository_url": {
                    "type": "string",
                    "example": "https://github.com/Armur-Ai/Armur-Code-Scanner"
                }
            }
        },
        "utils.ReportItem": {
            "type": "object",
            "properties": {
                "column": {
                    "type": "integer"
                },
                "confidence": {
                    "type": "string"
                },
                "file": {
                    "type": "string"
                },
                "line": {
                    "type": "integer"
                },
                "message": {
                    "type": "string"
                },
                "owasp": {
                    "type": "string"
                },
                "severity": {
                    "type": "string"
                },
                "suggested_remediation": {
                    "type": "string"
                }
            }
        },
        "utils.SANSReportItem": {
            "type": "object",
            "properties": {
                "column": {
                    "type": "integer"
                },
                "confidence": {
                    "type": "string"
                },
                "cwe": {
                    "type": "string"
                },
                "file": {
                    "type": "string"
                },
                "line": {
                    "type": "integer"
                },
                "message": {
                    "type": "string"
                },
                "severity": {
                    "type": "string"
                },
                "suggested_remediation": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "/",
	Schemes:          []string{},
	Title:            "Armur Code Scanner API",
	Description:      "This is a code scanner service API.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
