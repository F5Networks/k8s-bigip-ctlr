## Public F5 repository for data schemas. ##

Data schemas require a publically available repository for access. Schemas
used for the definition and validation of velcro structured data should placed
in this repository.

This provides:
- A central location for documentation and referencing purposes.
- Enforcement of unique ids and naming for consistent and reproducible
  validation.
- Globally accessible location and centralized well known location for
  retrieval.

### Example Schemas ###

The npm JSON Schema module allows for a custom resolver. This allows for schemas
to be published without setting their base resolution URI. Adding flexibility
throughout the development process and ease of use as the Velcro project
matures.

Instead of hard coding schema id URIs the system can replace the base URI with a
configured URI from the environment. This allows developers to run tests
locally, development environments pointed to a sandbox, and production
environments to be configured with the canonical, authoritative source.

#### Setup ####
To setup environment:
`npm install jsonschema commander`

#### Examples ####
To run with schemas from default URI: bldr-git/velcro/master
`node validate-data.js`

To run with schemas from local file system:
`node validate-data.js -t`

To provide a custom URI:
`node validate-data.js -b http://schemas.f5.example.com/`

#### What's Going On? ####
There are two schemas provided. One is a schema providing primitive types and
the second uses those types to validate some very simple data.

The definitions_v0.1.0.json provides a type for a positive integer, a negative
integer, and a non-empty string.

The enforce-basic-types_v0.1.0.json creates a simple schema that expects three
fields: non-empty-string-field, positive-integer-field, and
negative-integer-field. These three fields are restricted to the types defined
in definitions_v0.1.0.json (in a self-explanatory manner).

The data embedded in validate-data will fail with an error to show a
ValidationResult and to provide an exercise to the fix the embedded data.
