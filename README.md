# REST Replay

Tool to replay REST request in pipelines and other places.

rere.py will load REST Replay files to replay, can do some basic processing with the response.
The replay files are not intended to house complex logic, but instead work in tandem with other languages and systems for more complex tasks.

## Usage

`rere.py --dry --verbose script`

* `--dry` supresses requests, sets positive dummy data to response values
* `--verbose` for debugging
* `script` the REST Replay script to run

To create a simple script:
* Open the dev tools in your browser
* Make a request
* Right click and copy request headers
* Paste it into a text editor
* Copy paste the request body below between two identical lines (delimiters, see below)
* Add a line above with baseUrl scheme://netloc/

```
baseUrl https://example.tld/
PASTE REQUEST HEADERS

PASTE REQUEST BODY

# empty line above is important, if you want to use empty lines as delimiter
# if your body contains empty lines, use anything else that doesn't look like a header, like a dot or colon or whatever
```

These scripts are mostly compatible with .http/.rest files.

## Format

Empty lines and lines starting with # are comments

Meta commands start with a lowercase letter, and do not span more than one line. Request start with an upper case HTTP method.
Indentation is stripped for commands and the first line of requests.
The script steps are validated as they are executed, terminating early ony syntax errors.

e.g.
```bash
baseUri https://localhost:9200/
defaultHeader Authorization: {{ env.API_KEY }}

GET /index/_search
Content-Type: application/json
:
{
  query: { match: { _id: "someid" } }
}
:

mode elastic
GET /index/_search
{
  query: { match: { _id: "someid" } }
}
```

### Requests

#### .http / .rest mode

Requests by default are written very similar to raw HTTP requests with the following format:

```
METHOD URI
HEADERS
BODY
```

Valid methods are: `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`.

If the URI omits protocol and host part, it will be appended to the baseUri, if set. While header lines can be commented out, unless the request line itself is commented out, the body ignores comments.

The request is followed by 0 or more lines of headers, replacing over any set defaultHeader. The only forbidden header here is Content-Length, as it is replaced by the length of the body that follows.

The content body, in contrast to a raw HTTP request is delimited by any line after the headers that is not following `[\w-]+:\s*.+`.
The same delimiter is required after the request body, so Content-Length can be properly calculated, if templated or read from file.
If you do not have a body or know it does not contain empty lines, you can use those, although not recommended.

#### elasic mode

Alternatively you can switch to elastic mode, allowing you to copy paste elastic queries directly from the dev console.

```
METHOD URL
BODY
```

As with http / rest mode, you probably want to specify a baseUrl to request against. Elestic mode however does not allow you to set per request headers. You can use defaultHeader instead.

The optional body in elastic mode is not explicitly delimited, but has to be a json object or array instead. The request body is complete once the smallest possible amount of lines connected parse successfully, so do not add extra characters on the closing line!

### Meta Commands

Meta commands are case sensitive. Before execution, every command argument in \<> is ran through the templater. Words in CAPS are to be replaced, words with slashes are a choice.

* baseUrl \<URL>
  > The base url, can include a base path
* envFiles PATHS
  > A list of paths, absolute or relative to the REST Replay file, delimited by colon (trimmed)
* delimiter OPEN token CLOSE
  > Template values are delimited tokens that can be remapped here, if your format might already use that.
  > e.g. `delimiter (( token ))` to subsequentially use double parens.
  > *Default:* {{ token }}
* timeout AMOUNT
  > How long to wait until a request times out. If a request times out, it will rewrite the responseCode and continue.
  > Amount is in seconds by default, but can be suffixed with s/sec/m/min.
  > *Default:* 3s
* exit \<CODE>
  > Abort execution and return the exit code. If CODE is not numeric, 1 is used.
  > *Default:* 0
* defaultHeader \<NAME>: \<VALUE>
  > Set the default value for a given header. If value is empty, the default is unset.
* set \<KEY>: \<VALUE>
  > Set values outside any namespace to the given value. Key has to consist of `[\w-]` characters.
* parseTemplates \<VALUE>
  > Force parsing templates in value. If you have a literal value of "{{ foo }}" and foo is "bar", `parseTemplates result: {{ value }}` would set result to "bar".
* replace \<VALUE>: \<SED_STRING>
  > Use a sed s/// replacement expression on a template. The replacement is in-place.
  > The sed string has to start with a lowercase s, followed by a delimiter character picked by you. Immediately following the delimiter is the regular expression, and, after another separator, the replacement string. After the terminating delimiter, you can add the following flag characters:
  > * g - global, replace all occurances
  > * i - insensitive, ignore case
  > * m - multiline, ^.*$ matches the whole string instead of a line
  > * s - dotall, makes dot match line breaks
  >
  > Example: `replace key: s/search/replace/gi`
* read PATH: \<KEY>
  > Read the given file, absolute or relative to the REST Replay file, and write it's content into the template key.
* write PATH: \<VALUE>
  > At the specified path, absolute or relative to the REST Replay file, write the specified value.
* print \<VALUE>
  > Write some value to standard out / terminal
* mode elastic/http/rest
  > In rest/http mode you have to write full HTTP requests with headers.
  > In elastic mode headers are not parsed and the optional body delimits as soon as a json object or array beginning in the next line is complete. Use defaultHeader if you need them.
  > *Default:* rest
* cookies on/off
  > Turn cookie parsing on/off
  > *Default:* off
* storage new/AMOUNT PATH
  > Enable persitent storage for cookies.
  > * AMOUNT is a limit on how long cookies should be stored for.
  >   This counts mtime for the storage file, not cookie age. To keep sessions in tact, this is only checked when reloading cookies from disk.
  >   Just like with timeout, in seconds by default, with optional suffix. Default duration is 300s.
  > * Writing new instead of a duration equals 0s.
  > * PATH is an optional path, absolute or relative to the REST Replay file, where to store cookies to.
  > Defaults to /tmp/restreplay.cache on linux, C:\Users\\\<username>\AppData\Local\Temp on windows
  >
  > *Default:* unset, cookies are not stored on disc.
* sslContext OPTIONS/default
  > OPTIONS is a set of comma separated list of `key: value` pairs, with quoted values. Values can contain templates. These options map closely to the python [SSLContext](https://docs.python.org/3/library/ssl.html#ssl-contexts) object. All supported keys are optional. An abbreviated summary is provided for convenience. Check the linked python docs for more information. _**If unsure, leave unset**_. If you want to revert to default values, use `sslContext default` instead.
  > * cafile : path to a file of concatenated CA certificates in PEM format
  > * capath : path to a directory containing several CA certificates in PEM format
  > * mode :
  >   * NONE : just about any cert is accepted. Validation errors, such as untrusted or expired cert, are ignored and do not abort the TLS/SSL handshake
  >   * REQUIRED (default) : certificates are required from the other side of the socket connection; an SSLError will be raised if no certificate is provided, or if its validation fails. As PROTOCOL_TLS_CLIENT is set by default, this will validate hostnames.
  >   * UNCHECKED : This is like REQUIRED, but hostname checks are explicitly turned off. This mode is not sufficient to verify a certificate in client mode as it does not match hostnames.
  > * verify : (these are additive, so you have to re-add defaults if set)
  >   * CRL_UNCHECKED (default) : in this mode, certificate revocation lists (CRLs) are not checked (VERIFY_DEFAULT)
  >   * CRL_CHECK_LEAF : only the peer cert is checked but none of the intermediate CA certificates
  >   * CRL_CHECK_CHAIN : CRLs of all certificates in the peer cert chain are checked
  >   * X509_STRICT (default) : disable workarounds for broken X.509 certificates
  >   * ALLOW_PROXY_CERTS : enables proxy certificate verification
  >   * X509_TRUSTED_FIRST (default) : instructs OpenSSL to prefer trusted certificates when building the trust chain to validate a certificate
  >   * X509_PARTIAL_CHAIN (default) : instructs OpenSSL to accept intermediate CAs in the trust store to be treated as trust-anchors, in the same way as the self-signed root CA certificates
  > * protocol : (SSL2 / SSL3 are not supported)
  >   * TLS (default) : auto-negotiate the highest protocol version that both the client and server support
  >   * TLSv1.0 : selects TLS version 1.0 as the channel encryption protocol
  >   * TLSv1.1 : selects TLS version 1.1 as the channel encryption protocol
  >   * TLSv1.2 : selects TLS version 1.2 as the channel encryption protocol
  > * options : (protocol options are not supported, NO_SSLv2 | NO_SSLv3 are always set)
  >   * NO_RENEGOTIATION : disable all renegotiation in TLSv1.2 and earlier
  >   * ENABLE_MIDDLEBOX_COMPAT : send dummy Change Cipher Spec (CCS) messages in TLS 1.3 handshake to make a TLS 1.3 connection look more like a TLS 1.2 connection
  >   * NO_COMPRESSION : disable compression on the SSL channel
  >   * NO_TICKET : prevent client side from requesting a session ticket
  >   * IGNORE_UNEXPECTED_EOF : ignore unexpected shutdown of TLS connections
  >   * ENABLE_KTLS : enable the use of the kernel TLS
  >
  > example: `sslContext cafile: "/path/to/cacert.pem", protocol: "TLS", options: "NO_RENEGOTIATION, NO_COMPRESSION"`
* eval \<KEY>: \<EXRPESSION>
  > Run a java-script one-liner and store the result to KEY.
  > This requires js2py or pythonmonkey to be installed.
* if EXPRESSION
  > Evaluate the next command or request only if EXPRESSION holds true.

### Expressions

Expressions are really simple, without conjunction or disjunction (AND and OR). You can negate (NOT) and value compare. String and number literals are in JSON format, templates are safely resolved as values and dont use delimiters. Numeric comparisons are tried first, with string operations as fallback. Available comparisons are:

* strings and numbers: A == B , A != B
* numbers only: A < B , A <= B , A > B , A >= B, A in [ B .. C ]
* strings only: empty A, A in B, A matches B

If a value can not parse as number, numeric compare expressions will return false.

`A in [ B .. C ]` will be true if A is in the range of B and C (inclusive).

`A matches B` tests a string A against a regex B.

### Templates

Templates are simply replaced. Keys are `\w+` with `.` as namespace separator.

Environment variables are loaded into the `env` namespace and replaced by values in the envFiles, if specified.
Variables set through commands do not have a namespace.
Every request replaces the values in the `response` namespace. The only variables in that namespace are: `body`, `code` and `headers`

## Full example
```bash
envFile .env

read request_body.json: body
GET https://localhost:3000/main_endpoint
Authorization: {{ env.API_KEY }}
:
{{ body }}
:

set value: {{ response.body }}

if not {{ response.code }} in [ 200 .. 299 ]
  exit 1

write file.json: {{ value }}

```
