package scim

import "time"

// SCIM 2.0 types per RFC 7643/7644

const (
	ContentType = "application/scim+json"
	UserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

// User is the SCIM 2.0 User resource.
type User struct {
	Schemas      []string       `json:"schemas"`
	ID           string         `json:"id,omitempty"`
	ExternalID   string         `json:"externalId,omitempty"`
	UserName     string         `json:"userName,omitempty"`
	Name         *Name          `json:"name,omitempty"`
	DisplayName  string         `json:"displayName,omitempty"`
	Emails       []EmailValue   `json:"emails,omitempty"`
	Active       *bool          `json:"active,omitempty"`
	Meta         *Meta          `json:"meta,omitempty"`
	Groups       []GroupRef     `json:"groups,omitempty"`
	PhoneNumbers []PhoneValue   `json:"phoneNumbers,omitempty"`
}

type Name struct {
	Formatted   string `json:"formatted,omitempty"`
	FamilyName  string `json:"familyName,omitempty"`
	GivenName   string `json:"givenName,omitempty"`
	MiddleName  string `json:"middleName,omitempty"`
	HonorificPrefix  string `json:"honorificPrefix,omitempty"`
	HonorificSuffix  string `json:"honorificSuffix,omitempty"`
}

type EmailValue struct {
	Value   string `json:"value,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary *bool  `json:"primary,omitempty"`
}

type PhoneValue struct {
	Value   string `json:"value,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary *bool  `json:"primary,omitempty"`
}

type Meta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

type GroupRef struct {
	Value string `json:"value,omitempty"`
	Ref   string `json:"$ref,omitempty"`
	Type  string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
}

// Group is the SCIM 2.0 Group resource (maps to auth2 roles).
type Group struct {
	Schemas     []string   `json:"schemas"`
	ID          string     `json:"id,omitempty"`
	DisplayName string     `json:"displayName,omitempty"`
	Members     []MemberRef `json:"members,omitempty"`
	Meta        *Meta      `json:"meta,omitempty"`
}

type MemberRef struct {
	Value   string `json:"value,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
}

// ListResponse is the SCIM ListResponse schema.
type ListResponse struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	ItemsPerPage int           `json:"itemsPerPage,omitempty"`
	StartIndex   int           `json:"startIndex,omitempty"`
	Resources    []interface{} `json:"Resources"`
}

// ResourceType is SCIM service provider ResourceType.
type ResourceType struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Endpoint   string   `json:"endpoint"`
	Schema     string   `json:"schema"`
	Meta       *Meta    `json:"meta,omitempty"`
}

// Schema is the SCIM Schema discovery.
type Schema struct {
	Schemas    []string      `json:"schemas"`
	ID         string        `json:"id"`
	Name       string        `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	Attributes []SchemaAttr  `json:"attributes"`
}

type SchemaAttr struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Required   bool     `json:"required,omitempty"`
	Mutability string   `json:"mutability,omitempty"`
	Returned   string   `json:"returned,omitempty"`
}

// PatchOperation is SCIM PATCH operation (RFC 7644 §3.5.2).
type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// PatchRequest is the SCIM PATCH request body.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}
