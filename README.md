# Go jwtregistry

A hopefully simple JWT signing and validating registry that can be
used globally, referring to signing and validating contexts by named
purpose.

This was created to simplify code that uses many different JWT
issuers and validators, and needs to update their contents based
on changed configuration.

All values returned by the methods are thread-safe.  Values like keysets
provided during context creation must not be modfied after registration.

To update a named context, register a new one with the same name.

Not all validation options are provided, and sensible (opinionated)
validations and crypto algorithms used.
