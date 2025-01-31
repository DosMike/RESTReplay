#!/usr/bin/env python3
import argparse
import sys
import os
from urllib.parse import urlparse, urljoin, urlunparse, ParseResult as ParsedURL
from urllib.request import *
import re
from pathlib import Path
import time
from http.cookiejar import FileCookieJar, CookieJar
from http.client import HTTPResponse
from tempfile import gettempdir
import traceback
import json
import ssl
from typing import NoReturn


try:
    # try to use js2py
    import js2py
    def evalJs(code):
        return js2py.eval_js(code)
except:
    try:
        # maybe we have pythonmonkey?
        import pythonmonkey
        def evalJs(code):
            return pythonmonkey.eval(code)
    except:
        # ok, just die on call
        def evalJs(code):
            die('eval requires js2py or pythonmonkey')

version = '1.1.0'

verbose = False
dryRun = False
templates = dict([(f'env.{k}',v) for k,v in os.environ.items()])
baseUrl: ParsedURL = None
defaultHeader = {
    'User-Agent': f'RESTReplay/{version} (DosMike/Python3)',
    'Content-Type': 'application/json; charset=utf-8',
    'Accept': 'application/json, */*;q=0.8',
}
delimiter = ['{{','}}']
timeout = 3
requestParseMode = 'rest'

cookies: 'CookieJar|None' = None
cookiesEnabled = False
cookieStorage: 'str|None' = None

line = 0
testFilterState = True
sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


def die(message: str, code: int = 1) -> NoReturn:
    print(f'Line {line}:',message)
    sys.exit(code)


def getTemplate(name: str, pos: int) -> str:
    if not re.match(r'^[\w\.-]+$', name):
        die(f'Invalid characters in template "{name}" (offset {pos})')
    if name in templates:
        return templates[name]
    die(f'Template "{name}" not filled (offset {pos})')


def resolve(templated: str) -> str:
    # build escaped regex
    begin = re.escape(delimiter[0])
    end = re.escape(delimiter[1])
    regex = f'{begin}\\s*(.+?)\\s*{end}'
    return re.sub(regex, lambda x: getTemplate(x[1], x.pos), templated)


def parseDuration(value: str) -> int:
    match = re.match(r'^([0-9]+)(s(?:ec)?|m(?:in)?)?$', value)
    if not match:
        die('Invalid format for duration')
    baseValue = int(match[1])
    if match[2] and match[2][0] == 'm':
        return baseValue * 60
    else:
        return baseValue


def evalExpr(expr: str, requireCleanReturn: bool = True) -> tuple[bool, int]:
    regexJstr = r'"(?:\\[\\"rnt]|[^"])+"'
    regexJnum = r'-?[0-9]+(?:\.[0-9]+)?'
    regexJvalue = f'{regexJstr}|{regexJnum}'
    regexTemplate = r'[a-zA-Z][\w-]*(?:\.[\w-]+)?'
    regexBinOp = r'[!=]=|[<>]=?|in|matches'
    regexRange = f'\\[\\s*({regexJvalue}|{regexTemplate})\\s*\\.\\.\\s*({regexJvalue}|{regexTemplate})\\s*\\]'

    ilen = len(expr)
    expr = expr.lstrip()

    def popValue(val:str) -> tuple[str|int|float,str,int]:
        if re.match(r'^[-"0-9]', val):
            m: re.Match = re.match(f'^{regexJvalue}', val)
            if not m:
                die('Unexpected numeric parse failure')
            v = json.loads(m[0])
            return v, val[m.end():], m.end()
        else:
            m: re.Match = re.match(f'^{regexTemplate}', val)
            if not m:
                die(f'Invalid expression, number or template expected at "{val}"')

            if not m[0] in templates:
                raise ValueError(f'Invalid expression, can\'t compare unset templte {m[1]}')
            v = templates[m[0]]
            if re.match(r'^[0-9]+$', v):
                v = int(v)
            elif re.match(regexJnum, v):
                v = float(v)
            return v, val[m.end():], m.end()

    rightHand=None
    result: bool|None = None
    # check if we deal with a unary
    if expr.lower().startswith('not'):
        expr = expr[3:]
        [t,l] = evalExpr(expr, False)
        result = not t
        expr = expr[l:].lstrip()
    elif expr.lower().startswith('empty'):
        try:
            [v,expr,l] = popValue(expr)
            result = len(v.strip()) > 0 if isinstance(v,str) else v != 0
        except:
            v = 1
            result = True
    else:
        # has to be a binary now
        [leftHand, expr, l] = popValue(expr)

        expr = expr.lstrip()
        m = re.match(f"^{regexBinOp}", expr)
        if not m:
            die(f'Invalid expression, missing or invalid operator')
        op = m[0]
        expr = expr[len(op):].lstrip()

        if isinstance(leftHand, (int,float)):
            if op.lower() == 'in':
                m = re.match(f"^{regexRange}", expr)
                if not m:
                    leftHand = str(leftHand)
                else:
                    expr = expr[len(m[0]):].lstrip()
                    [min,_,_] = popValue(m[1])
                    [max,_,_] = popValue(m[2])
                    if not isinstance(min,(int,float)) or not isinstance(max,(int,float)):
                        die(f'Invalid expression, range min/max have to be numeric')
                    result = leftHand >= min and leftHand <= max
            else:
                [rightHand, expr, l] = popValue(expr)
                if not isinstance(rightHand, (int,float)):
                    result = False
                elif op == '==':
                    result = leftHand == rightHand
                elif op == '!=':
                    result = leftHand != rightHand
                elif op == '<':
                    result = leftHand < rightHand
                elif op == '<=':
                    result = leftHand <= rightHand
                elif op == '>':
                    result = leftHand >= rightHand
                elif op == '>=':
                    result = leftHand >= rightHand
                else:
                    die(f'Invalid expression, unknown operation "number {op} number"')
        if result == None and isinstance(leftHand, str):
            [rightHand, expr, l] = popValue(expr)
            if op.lower() == 'in':
                result = leftHand in str(rightHand)
            elif op.lower() == 'matches':
                result = True if re.match(str(rightHand), leftHand) else False
            elif op == '==':
                result = leftHand == str(rightHand)
            elif op == '!=':
                result = leftHand != str(rightHand)
            elif isinstance(rightHand, (int,float)):
                result = False
            else:
                die(f'Invalid expression, unknown operation "text {op} text"')

    if requireCleanReturn and len(expr.strip()):
        die(f'Invalid expression, End of Line expected (remainder: {expr})')

    return result, ilen-len(expr)


def filtered(callback, args: str|tuple):
    global testFilterState
    s = testFilterState
    testFilterState = True  # run next command again

    if not s:
        return None
    elif isinstance(args, str):
        return callback(args)
    else:
        return callback(*args)


def cmdBaseUrl(args: str):
    global baseUrl
    baseUrl = urlparse(resolve(args))
    if not baseUrl.scheme or not baseUrl.netloc:
        die('Invalid value for baseUrl: requires scheme and host')
    if baseUrl.query or baseUrl.fragment:
        die('Invalid value for baseUrl: can not contain query or fragment')
    if verbose:
        print('Set baseUrl to',urlunparse(baseUrl))


def cmdEnvFiles(args: str):
    global templates
    paths = args.split(':')
    for path in paths:
        if not os.path.isfile(path):
            die(f'Could not open env file {os.path.abspath(path)}')
        if verbose:
            print('Reading env file',os.path.abspath(path))
        with open(path) as f:
            for line in (line.lstrip(' \t').rstrip('\r\n') for line in f.readlines()):
                if len(line) == 0 or line.startswith('#'):
                    continue
                key = line.split('=',1)[0]
                value = line[len(key)+1:]
                templates[f'env.{key.strip()}'] = value


def cmdDelimiter(args: str):
    global delimiter
    match = re.match(r'^([^\s]+)\s*token\s*([^\s]+)$', args)
    if not match:
        die('Invalid syntax for delimiter')
    delimiter = [match[1], match[2]]
    if verbose:
        print('Set delimiter to',delimiter[0],'token',delimiter[1])


def cmdTimeout(args: str):
    global timeout
    timeout = parseDuration(args.strip())
    if verbose:
        print('Set timeout to',timeout,'sec')


def cmdExit(args: str):
    try:
        code = int(resolve(args).strip())
        sys.exit(code)
    except Exception as e:
        die(f'Exit not called with integer ({args}):\n{e}')


def cmdDefaultHeader(args: str):
    global defaultHeader

    match = re.match(r'^([\w-]+):\s*(.*)$', args)
    if not match:
        die('Invalid format for defaultHeader')
    key = resolve(match[1])
    value = resolve(match[2]) if match[2] else ''

    if value:
        defaultHeader[key] = value
        if verbose:
            print('Set defaultHeader',key,':',value or '<UNSET>')
    elif key in defaultHeader:
        defaultHeader.pop(key)
        if verbose:
            print('Cleared defaultHeader',key)
    elif verbose:
        print(f'Tried to clear defaultHeader "{key}", but was not set')


def cmdSet(args: str):
    global templates

    key = args.split(':',1)[0]
    value = args[len(key)+1:]
    key = resolve(key.strip())
    value = resolve(value.strip())
    if not re.match(r'^[\w-]+$', key):
        die(f'Invalid format of key "{key}" in set')

    if value:
        templates[key] = value
        if verbose:
            print(f'Set template "{key}" : "{value}"')
    else:
        templates.pop(key)
        if verbose:
            print(f'Cleared template "{key}"')


def cmdParseTemplate(args: str):
    global templates

    key = resolve(args.strip())
    if not re.match(r'^[\w-]+$', key):
        die(f'Invalid format of key "{key}" in parseTemplate')
    value = resolve(key.strip())

    if value:
        templates[key] = value
        if verbose:
            print(f'Set template "{key}" : "{value}"')
    else:
        templates.pop(key)
        if verbose:
            print(f'Cleared template "{key}"')


def cmdReplace(args: str):
    global templates

    key = args.split(':',1)[0]
    value = args[len(key)+1:]
    key = resolve(key.strip())
    value = resolve(value.strip())
    if not re.match(r'^[\w-]+$', key):
        die(f'Invalid format of key "{key}" in replace')
    if not key in templates:
        die(f'Invalid call to replace, key "{key}" is unset')

    if len(value) < 4 or value[0] != 's':
        die('Invalid format for sed expression')

    delim = value[1]
    idx2 = value.find(delim, 2)
    idx3 = value.find(delim, idx2+1)
    if idx2 == -1 or idx3 == -1:
        die('Invalid format for sed expression')
    pattern = value[2,idx2]
    replacement = value[idx2+1,idx3]
    flags = 0
    g = False
    for c in value[idx3+1:].lower():
        if c == 'g':
            g = True
        elif c == 'i':
            flags = flags | re.IGNORECASE
        elif c == 's':
            flags = flags | re.DOTALL
        elif c == 'm':
            flags = flags | re.MULTILINE
        else:
            die(f'Unknown regex flag {c} (Expected zero or more of: G, I, S, M)')

    value = re.sub(pattern, replacement, templates[key], 0 if g else 1, flags)

    if value:
        templates[key] = value
        if verbose:
            print(f'SED set template "{key}" : "{value}"')
    else:
        templates.pop(key)
        if verbose:
            print(f'SED cleared template "{key}"')


def cmdRead(args: str):
    global templates

    file = args.split(':',1)[0]
    key = args[len(file)+1:]
    key = resolve(key.strip())
    file = os.path.abspath(file.strip())
    if not re.match(r'^[\w-]+$', key):
        die(f'Invalid format of key "{key}" in set')
    if not os.path.isfile(file):
        die(f'Can not read form file "{file}"')
    with open(file) as f:
        templates[key] = f.read()

    if verbose:
        print(f'Read template "{key}" from file {file}')


def cmdWrite(args: str):
    file = args.split(':',1)[0]
    value = args[len(file)+1:]
    value = resolve(value.strip())
    file = os.path.abspath(file.strip())
    with open(file, 'w') as f:
        f.write(value)
        f.flush()

    if verbose:
        print(f'Wrote value to file {file}')


def cmdPrint(args: str):
    print(resolve(args.strip()))


def cmdMode(args: str):
    global requestParseMode

    if args.lower() == 'elastic':
        requestParseMode = 'elastic'
    elif args.lower() in ('rest', 'http'):
        requestParseMode = 'rest'
    else:
        die(f'Unknown request parse mode "{args}"')

    if verbose:
        print(f'Set mode to {requestParseMode}')


def updateStorage():
    global cookies

    if not cookiesEnabled:
        cookies = None
    elif cookieStorage:
        cookies = FileCookieJar(cookieStorage)
        cookies.load()
    else:
        cookies = CookieJar()


def cmdCookies(args: str):
    global cookies
    global cookiesEnabled

    v = args.strip()
    if not v in ('on','off'):
        die('Invalid format for cookies, can only be on/off')
    cookiesEnabled = v == 'on'
    updateStorage()

    if verbose:
        print('Set cookies', v)


def cmdStorage(args: str):
    global cookieStorage

    part = args.split(' ',1)[0]
    args = args[len(part):].lstrip()
    storageTimeout = 0 if part == 'new' else parseDuration(part)
    storagePath = args or os.path.join(gettempdir(), 'defaultstore.restreplay')
    if re.match(r'[:;<>"\\/|?*\x00-\x31]'):
        die("Storage path has invalid character")
    cookieStorage = storagePath
    if os.path.isfile(cookieStorage):
        if time.time() - os.path.getmtime(cookieStorage) > storageTimeout:
            os.unlink(cookieStorage)
    updateStorage()

    if verbose:
        print(f'Set storage to {storageTimeout}sec at',storagePath)


def cmdSslContext(args: str):
    global sslContext

    if args.strip().lower() == 'default':
        sslContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        return

    kvStore: 'dict[str,str]' = dict()
    knownKeys = ('cafile', 'capath', 'certfile', 'keyfile', 'password', 'protocol', 'mode', 'verify', 'options')
    regexValue = r'"(?:\\[\\"rnt]|[^\\])+?"'
    regexKeyValue = f'\\w+\\s*:\\s*{regexValue}'
    regexConfig = f'^{regexKeyValue}(?:\\s*,\\s*{regexKeyValue})*$'
    if not re.match(regexConfig, args):
        die('Invalid key value syntax for sslContext arguments')
    # capture one key value and eat the possible delimiter
    regexKeyValue = re.compile(f'^(\\w+)\\s*:\\s*({regexValue})(?:\\s*,\\s*)?')
    while args:
        match = regexKeyValue.match(args)
        key = match[1].lower()
        try:
            value = resolve(json.loads(match[2]))
        except Exception as e:
            die(f'Invalid value for key {key} : {match[2]}')
        args = args[len(match[0]):]
        if not key in knownKeys:
            die(f'Unknown sslContext parameter: {key}')
        kvStore[key] = value

    cafile = kvStore.get('cafile', None)
    capath = kvStore.get('capath', None)
    try:
        sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cafile, capath=capath)
    except Exception as e:
        if verbose:
            traceback.print_exc()
        die(f'Failed to create sslContext')

    certfile = kvStore.get('certfile', None)
    keyfile = kvStore.get('keyfile', None)
    password = kvStore.get('password', None)
    if certfile:
        if password != None:
            passfun = lambda : templates.get(password) if password in templates else die('Template for SSL Certificat KeyFile Password was not set')
        else:
            passfun = None
        sslContext.load_cert_chain(certfile, keyfile, passfun)

    if 'protocol' in kvStore:
        rawProtocol = kvStore['protocol'].lower()
        if rawProtocol == 'tlsv1.0':
            sslContext.minimum_version = ssl.TLSVersion.TLSv1
            sslContext.maximum_version = ssl.TLSVersion.TLSv1
        elif rawProtocol == 'tlsv1.1':
            sslContext.minimum_version = ssl.TLSVersion.TLSv1_1
            sslContext.maximum_version = ssl.TLSVersion.TLSv1_1
        elif rawProtocol == 'tlsv1.2':
            sslContext.minimum_version = ssl.TLSVersion.TLSv1_2
            sslContext.maximum_version = ssl.TLSVersion.TLSv1_2
        elif rawProtocol == 'tls':
            pass  # default for PROTOCOL_TLS
        else:
            die('Unsupported protocol version (expected one of: TLS, TLSv1.0, TLSv1.1, TLSv1.2)')

    if 'mode' in kvStore:
        rawVerifyMode = kvStore['mode'].lower()
        if rawVerifyMode == 'none':
            sslContext.verify_mode = ssl.CERT_NONE
        elif rawVerifyMode == 'required':
            sslContext.verify_mode = ssl.CERT_REQUIRED
        elif rawVerifyMode == 'unchecked':
            sslContext.verify_mode = ssl.CERT_REQUIRED
            sslContext.check_hostname = False
        else:
            die('Unsupported mode (expected one of: NONE, REQUIRED)')

    if 'verify' in kvStore:
        rawVerifyFlags = [x.strip().lower() for x in kvStore['verify'].split(',')]
        verifyFlags = ssl.VerifyFlags.VERIFY_DEFAULT
        for flag in rawVerifyFlags:
            if flag == 'crl_uncheck':
                pass
            if flag == 'crl_check_leaf':
                verifyFlags = verifyFlags | ssl.VerifyFlags.VERIFY_CRL_CHECK_LEAF
            elif flag == 'crl_check_chain':
                verifyFlags = verifyFlags | ssl.VerifyFlags.VERIFY_CRL_CHECK_CHAIN
            elif flag == 'x509_strict':
                verifyFlags = verifyFlags | ssl.VerifyFlags.VERIFY_X509_STRICT
            elif flag == 'allow_proxy_certs':
                verifyFlags = verifyFlags | ssl.VerifyFlags.VERIFY_ALLOW_PROXY_CERTS
            elif flag == 'x509_trusted_first':
                verifyFlags = verifyFlags | ssl.VerifyFlags.VERIFY_X509_TRUSTED_FIRST
            elif flag == 'x509_partial_chain':
                verifyFlags = verifyFlags | ssl.VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
            else:
                die(f'Unknown verify flag {flag} (expected one or more of: CRL_UNCHECK, CRL_CHECK_LEAF, CRL_CHECK_CHAIN, X509_STRICT, ALLOW_PROXY_CERTS, X509_TRUSTED_FIRST, X509_PARTIAL_CHAIN)')
        sslContext.verify_flags = verifyFlags

    if 'options' in kvStore:
        rawOptions = [x.strip().lower() for x in kvStore['options'].split(',')]
        options = ssl.OP_ALL | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        for option in rawOptions:
            if option == 'no_renegotiation':
                options = options | ssl.OP_NO_RENEGOTIATION
            elif option == 'enable_middlebox_compat':
                options = options | ssl.OP_ENABLE_MIDDLEBOX_COMPAT
            elif option == 'no_compression':
                options = options | ssl.OP_NO_COMPRESSION
            elif option == 'no_ticket':
                options = options | ssl.OP_NO_TICKET
            elif option == 'ignore_unexpected_eof':
                options = options | ssl.OP_IGNORE_UNEXPECTED_EOF
            elif option == 'enable_ktls':
                options = options | ssl.OP_ENABLE_KTLS
            else:
                die(f'Unsupported option {option} (expected one or more of: NO_RENEGOTIATION, ENABLE_MIDDLEBOX_COMPAT, NO_COMPRESSION, NO_TICKET, IGNORE_UNEXPECTED_EOF, ENABLE_KTLS)')
        sslContext.options = options

    if verbose:
        print(f'Set up SSL Context')


def cmdEval(args: str):
    global templates

    key = args.split(':',1)[0]
    value = args[len(key)+1:].strip()
    key = key.strip()

    result = evalJs(resolve(value))
    if isinstance(result, (int,float,str)):
        die('Evaluation result is not numeric or string')

    if result:
        templates[key] = result
        if verbose:
            print('Set',key,'to',result,'<-',value)
    else:
        templates.pop(key)
        if verbose:
            print('Cleared',key,'from <-',value)


def cmdIf(args: str) -> bool:
    global testFilterState
    [testFilterState,_] = evalExpr(args)


def makeRequest(method: str, url: str, header: 'dict[str,str]', body: str):
    global templates

    if dryRun:
        templates['response.code'] = 201 if method in ('PUT','POST','PATCH') else 200
        templates['response.body'] = 'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.'
        templates['response.header'] = f"Content-Length: {len(templates['response.body'])}\r\nContent-Type: text/plain\r\nX-RestReplay: dryrun\r\n"
        time.sleep( min( max( timeout / 10, 0.1 ), 1.0 ) )
    else:
        urlParts = urlparse(urljoin(urlunparse(baseUrl), url)) if baseUrl else urlparse(url)
        if not urlParts.scheme or not urlParts.netloc:
            die(f'Request URL is invalid: {urlunparse(urlParts)}')
        if not urlParts.scheme in ('http','https'):
            die(f'Request URL uses an unsupported schema: http or https expected')

        header['Content-Length'] = len(body)
        if not 'Content-Type' in header:
            header['Content-Type'] = 'text/plain'

        try:
            request = Request(urlunparse(urlParts), body.encode(), header, method=method)
            director = OpenerDirector()
            director.add_handler(HTTPHandler(2 if verbose else 0))
            director.add_handler(HTTPSHandler(2 if verbose else 0, sslContext))
            director.add_handler(HTTPRedirectHandler())
            if cookies:
                director.add_handler(HTTPCookieProcessor(cookies))
            response: 'HTTPResponse' = director.open(request, timeout=timeout)
            templates['response.code'] = response.status
            templates['response.header'] = '\n'.join([f"{k}: {v}" for k,v in response.getheaders()])
            templates['response.body'] = response.read().decode()
        except Exception as e:
            if verbose:
                traceback.print_exc()
            die(f"Unexpected error during request\n{str(e)}")

    if verbose:
        print('Request completed with code',str(templates['response.code']))


def parseBodyRest(script: list[str]) -> tuple[list[str], dict[str,str], str]:
    header = dict(defaultHeader.items())
    # headers here need to have _some_ value (unless comment)
    while re.match(r'^\s*#|^[\w-]+:\s*[^\s]', script[0]):
        hdr = script.pop(0)
        line = line + 1
        if hdr.lstrip().startswith('#'):
            continue
        key = hdr.split(':',1)[0]
        value = hdr[len(key)+1:].strip()
        key = resolve(key)
        value = resolve(value)
        header[key.strip()] = value
        if verbose:
            print('Push header',key,':',value)

    # collect body from one delimiter to the other
    bodyDelimiter = script.pop(0)
    line = line + 1
    if verbose:
        print('Body delimiter',bodyDelimiter.strip())
    try:
        endIndex = script.index(bodyDelimiter)
        body = ''.join((resolve(line) for line in script[:endIndex]))
        line = line + endIndex
        script = script[endIndex+1:]
        if verbose:
            print('Collected',endIndex,'lines from script for body')
    except ValueError:
        die('Request body is never closed')

    return script, header, body


def parseBodyElastic(script: list[str]) -> tuple[list[str], dict[str,str], str]:
    # body needs to be a json document
    line1trimmed = script[0].strip()
    if not line1trimmed.startswith('{') and not line1trimmed.startswith('['):
        return script, dict(), ''

    def jsonComplete(v: str) -> bool:
        try:
            json.loads(v)
            return True
        except:
            return False

    terminal = '}' if line1trimmed.startswith('{') else ']'
    lines = 0
    body = ''
    while True:
        body = body + script.pop(0)
        lines = lines + 1
        if body.rstrip().endswith(terminal) and jsonComplete(body):
            break
        elif script.count == 0:
            die('Request body is never closed properly')
    if lines and verbose:
            print('Collected',lines,'lines from script for body')

    return script, dict(), body


def parseBody(script: list[str]) -> tuple[list[str], dict[str,str], str]:
    if requestParseMode == 'rest':
        return parseBodyRest(script)
    else:
        return parseBodyElastic(script)


def main(script: 'list[str]') -> int:
    global line

    while len(script):
        line = line + 1
        cmd = script.pop(0).lstrip()
        if len(cmd) == 0 or cmd.startswith('#'):
            continue
        word1 = cmd.split(' ',1)[0].rstrip()
        rest = cmd[len(word1):].strip()

        if word1 == 'baseUrl':
            filtered(cmdBaseUrl, rest)
        elif word1 == 'envFiles':
            filtered(cmdEnvFiles, rest)
        elif word1 == 'delimiter':
            filtered(cmdDelimiter, rest)
        elif word1 == 'timeout':
            filtered(cmdTimeout, rest)
        elif word1 == 'exit':
            filtered(cmdExit, rest)
        elif word1 == 'defaultHeader':
            filtered(cmdDefaultHeader, rest)
        elif word1 == 'set':
            filtered(cmdSet, rest)
        elif word1 == 'parseTemplates':
            filtered(cmdParseTemplate, rest)
        elif word1 == 'replace':
            filtered(cmdReplace, rest)
        elif word1 == 'read':
            filtered(cmdRead, rest)
        elif word1 == 'write':
            filtered(cmdWrite, rest)
        elif word1 == 'print':
            filtered(cmdPrint, rest)
        elif word1 == 'mode':
            filtered(cmdMode, rest)
        elif word1 == 'cookies':
            filtered(cmdCookies, rest)
        elif word1 == 'storage':
            filtered(cmdStorage, rest)
        elif word1 == 'sslContext':
            filtered(cmdSslContext, rest)
        elif word1 == 'eval':
            filtered(cmdEval, rest)
        elif word1 == 'if':
            cmdIf(rest)

        elif word1 in ('GET','HEAD','POST','PUT','DELETE','PATCH'):
            if verbose:
                print('Start',word1,'Request to',rest.rstrip())
            [script, header, body] = parseBody(script)

            filtered(makeRequest, (word1, rest.rstrip(), header, body))

        else:
            die(f'Unknown command or request method "{word1}"')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
             prog='REST Replay',
             description='Replay templated rest requests',
             epilog=f'Version {version} - https://github.com/DosMike/RestReplay')
    parser.add_argument('script', type=Path, nargs='?', help='The REST Replay script to run. Use dash to read from stdin. If omitted, displays help.')
    parser.add_argument('--dry', action='store_true', help='Make a dry run. Requests are not actually fired but response values are filled with values. Because the response body often requires structure, mileage will vary.')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging, for debugging purposes.')
    parser.add_argument('--version', action='store_true', help='Ignore everything and print version.')
    args = parser.parse_args(sys.argv[1:])

    if args.version:
        die(f'REST Replay - Version {version}', 0)
    elif not args.script:
        parser.print_help()
        exit()

    verbose = args.verbose
    dryRun = args.dry
    # we want relative files to be relative to the script, not PWD, so chdir
    if str(args.script) == '-':
        main([line for line in sys.stdin.readlines()])
    elif not os.path.isfile(args.script):
        die('Could not open script file')
    else:
        absScript = os.path.abspath(args.script)
        os.chdir(os.path.dirname(absScript))
        # now read and run
        with open(absScript,'r') as f:
            main([line for line in f.readlines()])
