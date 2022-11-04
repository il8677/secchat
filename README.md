# server
## layered security
The entire attack surface was limited to the initial call to verify_request; when the packet leaves this function, it has the proverbial stamp of approval. However, each module is designed to be self sufficient, so the msg will be further checked with calls to the database API, to ensure, for example, that the registration handler isn't handling a login message. The strings are also assumed to be malformed, and null termination is explicity set to avoid overflowing into the database, this is despite the fact that null termination is explicitly checked for in the verify_request function.

## request verification
The verify-request function double checks if a request if safe.
### request authentication

### sanity check
The struct needs to be as safe as we created it ourselves, so null termination of strings is checked. since the struct is a union, a lot of the checks are code-duplicated, but keeping the checks seperate encourages explicit checks for other factors if needed.