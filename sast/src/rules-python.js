// Python vulnerability detection rules. Mirrors the 11 categories used by
// the JS ruleset, with Python-idiomatic patterns (hashlib, subprocess,
// random module, Flask request, pymongo, pickle, yaml.load, etc.).

export const pythonRules = [
    {
        id: 'HARDCODED_SECRET',
        name: 'Hardcoded Secret',
        severity: 'HIGH',
        patterns: [
            // Accept both `=` (variable assignment) and `:` (dict literal key/value).
            // Optional closing quote after the key name handles quoted dict keys:
            // `'api_key': 'value'` as well as `api_key = 'value'`.
            { regex: /(?:api[_-]?key|apikey)['"]?\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded API key' },
            { regex: /(?:password|passwd|pwd)['"]?\s*[:=]\s*['"][^'"]{4,}['"]/gi, desc: 'Hardcoded password' },
            { regex: /(?:secret[_-]?key|secretkey)['"]?\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded secret key' },
            { regex: /(?:access[_-]?token|accesstoken)['"]?\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/gi, desc: 'Hardcoded access token' },
            { regex: /(?:aws[_-]?access[_-]?key[_-]?id)['"]?\s*[:=]\s*['"][A-Z0-9]{20}['"]/gi, desc: 'AWS Access Key ID' },
            { regex: /(?:aws[_-]?secret[_-]?access[_-]?key)['"]?\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, desc: 'AWS Secret Access Key' },
            { regex: /['"]sk[_-]live[_-][a-zA-Z0-9]{24,}['"]/g, desc: 'Stripe secret key' },
            { regex: /['"]ghp_[a-zA-Z0-9]{36,}['"]/g, desc: 'GitHub personal access token' },
        ],
        message: 'Hardcoded secret detected. Move secrets to environment variables.',
    },
    {
        id: 'SQL_INJECTION',
        name: 'SQL Injection Risk',
        severity: 'HIGH',
        patterns: [
            // f-string in execute(): cursor.execute(f"SELECT ...")
            { regex: /(?:execute|executemany)\s*\(\s*f['"]/gi, desc: 'f-string in SQL execute()' },
            // .format() in execute: cursor.execute("...".format(...))
            { regex: /(?:execute|executemany)\s*\(\s*['"][^'"]*['"]\s*\.\s*format\s*\(/gi, desc: '.format() in SQL execute()' },
            // %-formatting: cursor.execute("..." % ...)
            { regex: /(?:execute|executemany)\s*\(\s*['"][^'"]*['"]\s*%\s/gi, desc: '%-formatting in SQL execute()' },
            // String concat in CRUD verbs. Uses .* (no greedy quote matching) because
            // SQL strings commonly contain embedded single quotes like `WHERE x = '`.
            { regex: /(?:execute|executemany)\s*\(\s*['"]\s*SELECT.*\+/gi, desc: 'String concatenation in SELECT query' },
            { regex: /(?:execute|executemany)\s*\(\s*['"]\s*INSERT.*\+/gi, desc: 'String concatenation in INSERT query' },
            { regex: /(?:execute|executemany)\s*\(\s*['"]\s*UPDATE.*\+/gi, desc: 'String concatenation in UPDATE query' },
            { regex: /(?:execute|executemany)\s*\(\s*['"]\s*DELETE.*\+/gi, desc: 'String concatenation in DELETE query' },
        ],
        message: 'Potential SQL injection vulnerability. Use parameterized queries (e.g. cursor.execute(sql, params)) instead.',
    },
    {
        id: 'NOSQL_INJECTION',
        name: 'NoSQL Injection Risk',
        severity: 'HIGH',
        patterns: [
            // pymongo uses snake_case: find, find_one, update_one, delete_one
            { regex: /\.\s*find\s*\(\s*request\.(json|args|form|data|values)/gi, desc: 'Direct user input in MongoDB find()' },
            { regex: /\.\s*find_one\s*\(\s*request\.(json|args|form|data|values)/gi, desc: 'Direct user input in MongoDB find_one()' },
            { regex: /\.\s*update_one\s*\(\s*request\.(json|args|form|data|values)/gi, desc: 'Direct user input in MongoDB update_one()' },
            { regex: /\.\s*delete_one\s*\(\s*request\.(json|args|form|data|values)/gi, desc: 'Direct user input in MongoDB delete_one()' },
            { regex: /\.\s*update_many\s*\(\s*request\.(json|args|form|data|values)/gi, desc: 'Direct user input in MongoDB update_many()' },
            // $where operator literal in dict syntax
            { regex: /['"]\$where['"]\s*:/g, desc: '$where operator in MongoDB query' },
        ],
        message: 'Potential NoSQL injection vulnerability. Sanitize user input before using in database queries.',
    },
    {
        id: 'XSS',
        name: 'Cross-Site Scripting (XSS)',
        severity: 'HIGH',
        patterns: [
            // Flask: render_template_string takes a template string and renders it —
            // if the string is built from user input, that's classic XSS.
            { regex: /render_template_string\s*\(/g, desc: 'Flask render_template_string usage' },
            // Django: mark_safe / SafeString bypass autoescaping
            { regex: /\bmark_safe\s*\(/g, desc: 'Django mark_safe usage' },
            // Jinja `|safe` filter
            { regex: /\|\s*safe\b/g, desc: 'Jinja |safe filter usage' },
            // Flask Markup() wraps a value as already-safe HTML
            { regex: /\bMarkup\s*\(/g, desc: 'Flask Markup() usage' },
            // HttpResponse with f-string built from request data
            { regex: /HttpResponse\s*\(\s*f['"][^'"]*\{[^}]*request\./gi, desc: 'HttpResponse with user input in f-string' },
        ],
        message: 'Potential XSS vulnerability. Avoid bypassing template autoescaping with untrusted input.',
    },
    {
        id: 'PATH_TRAVERSAL',
        name: 'Path Traversal',
        severity: 'HIGH',
        patterns: [
            // open() with direct request data
            { regex: /\bopen\s*\(\s*request\.(json|args|form|data|files|values)/gi, desc: 'User input directly in open()' },
            // open() with concatenated request data
            { regex: /\bopen\s*\([^)]*\+\s*request\.(json|args|form|data|files|values)/gi, desc: 'User input concatenated in file path' },
            // os.path.join with request data
            { regex: /os\.path\.join\s*\([^)]*request\.(json|args|form|data|files|values)/gi, desc: 'User input in os.path.join()' },
            // Pathlib Path() with request data
            { regex: /\bPath\s*\(\s*request\.(json|args|form|data|files|values)/gi, desc: 'User input in pathlib Path()' },
            // Flask send_file with request data
            { regex: /send_file\s*\(\s*request\.(json|args|form|data|files|values)/gi, desc: 'User input in Flask send_file()' },
            // Literal traversal sequence
            { regex: /['"][^'"]*\.\.\/[^'"]*['"]/g, desc: 'Path traversal sequence detected' },
        ],
        message: 'Potential path traversal vulnerability. Validate and sanitize file paths.',
    },
    {
        id: 'INSECURE_RANDOM',
        name: 'Insecure Randomness',
        severity: 'MEDIUM',
        patterns: [
            // random module is not cryptographically secure
            { regex: /\brandom\.random\s*\(\s*\)/g, desc: 'random.random() is not cryptographically secure' },
            { regex: /\brandom\.randint\s*\(/g, desc: 'random.randint() is not cryptographically secure' },
            { regex: /\brandom\.choice\s*\(/g, desc: 'random.choice() is not cryptographically secure' },
            { regex: /\brandom\.choices\s*\(/g, desc: 'random.choices() is not cryptographically secure' },
            { regex: /\brandom\.uniform\s*\(/g, desc: 'random.uniform() is not cryptographically secure' },
            // Security-sensitive context — matches when a random call is on the same line as a sensitive keyword
            { regex: /\brandom\.(?:random|randint|choice|choices|uniform|sample)\s*\([^)]*\).*(?:token|password|secret|key|auth|session)/gi, desc: 'random module used for security-sensitive value' },
        ],
        message: 'Python random module is not cryptographically secure. Use the secrets module instead.',
    },
    {
        id: 'SENSITIVE_DATA_LOG',
        name: 'Sensitive Data Logging',
        severity: 'MEDIUM',
        patterns: [
            // print() with sensitive keywords
            { regex: /\bprint\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, desc: 'print() with password' },
            { regex: /\bprint\s*\([^)]*(?:token|secret|apikey|api_key)[^)]*\)/gi, desc: 'print() with sensitive token/key' },
            { regex: /\bprint\s*\([^)]*(?:creditcard|credit_card|ssn|social_security)[^)]*\)/gi, desc: 'print() with sensitive personal data' },
            // logging module
            { regex: /logging\.(debug|info|warning|warn|error|critical|exception)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, desc: 'Logging password' },
            { regex: /logging\.(debug|info|warning|warn|error|critical|exception)\s*\([^)]*(?:token|secret|apikey|api_key)[^)]*\)/gi, desc: 'Logging sensitive token/key' },
            // logger / log object pattern
            { regex: /\b(?:logger|log)\.(debug|info|warning|warn|error|critical|exception)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)/gi, desc: 'Logger call with password' },
            { regex: /\b(?:logger|log)\.(debug|info|warning|warn|error|critical|exception)\s*\([^)]*(?:token|secret|apikey|api_key)[^)]*\)/gi, desc: 'Logger call with sensitive token/key' },
        ],
        message: 'Sensitive data may be logged. Remove or mask sensitive information in logs.',
    },
    {
        id: 'HARDCODED_IP',
        name: 'Hardcoded IP Address',
        severity: 'MEDIUM',
        patterns: [
            // Same IPv4 patterns as JS — string literals are universal.
            { regex: /['"](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)['"]/g, desc: 'Hardcoded IPv4 address' },
            { regex: /['"](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d+['"]/g, desc: 'Hardcoded IP with port' },
        ],
        message: 'Hardcoded IP address found. Use environment variables or configuration files.',
    },
    {
        id: 'INSECURE_FUNCTION',
        name: 'Insecure Function Usage',
        severity: 'HIGH',
        patterns: [
            { regex: /\beval\s*\(/g, desc: 'Usage of eval()' },
            { regex: /\bexec\s*\(/g, desc: 'Usage of exec()' },
            { regex: /\bos\.system\s*\(/g, desc: 'Usage of os.system()' },
            { regex: /\bos\.popen\s*\(/g, desc: 'Usage of os.popen()' },
            // subprocess with shell=True is the dangerous form
            { regex: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g, desc: 'subprocess with shell=True' },
            // pickle deserialization of untrusted data → arbitrary code execution
            { regex: /\bpickle\.loads?\s*\(/g, desc: 'pickle.load/loads — unsafe deserialization' },
            // yaml.load without explicit SafeLoader is unsafe (yaml.safe_load is the fix)
            { regex: /\byaml\.load\s*\((?![^)]*SafeLoader)/g, desc: 'yaml.load() without SafeLoader' },
            // marshal is another unsafe deserialization avenue
            { regex: /\bmarshal\.loads?\s*\(/g, desc: 'marshal.load/loads — unsafe deserialization' },
        ],
        message: 'Insecure function detected. These functions can execute arbitrary code or deserialize untrusted data.',
    },
    {
        id: 'SECURITY_TODO',
        name: 'Security TODO/FIXME',
        severity: 'LOW',
        patterns: [
            // Python uses `#` for comments instead of `//`
            { regex: /#\s*TODO:?\s*.*(?:security|auth|password|token|secret|vuln|hack|fix)/gi, desc: 'Security-related TODO comment' },
            { regex: /#\s*FIXME:?\s*.*(?:security|auth|password|token|secret|vuln|hack)/gi, desc: 'Security-related FIXME comment' },
            { regex: /#\s*XXX:?\s*.*(?:security|auth|password|token|secret|vuln|hack)/gi, desc: 'Security-related XXX comment' },
            { regex: /#\s*HACK:?\s*.*/gi, desc: 'HACK comment found' },
        ],
        message: 'Security-related comment found. Ensure this is addressed before production.',
    },
    {
        id: 'WEAK_CRYPTO',
        name: 'Weak Cryptography',
        severity: 'MEDIUM',
        patterns: [
            { regex: /hashlib\.md5\s*\(/g, desc: 'MD5 hash usage' },
            { regex: /hashlib\.sha1\s*\(/g, desc: 'SHA1 hash usage' },
            { regex: /hashlib\.new\s*\(\s*['"]md5['"]/gi, desc: 'MD5 hash usage via hashlib.new' },
            { regex: /hashlib\.new\s*\(\s*['"]sha1['"]/gi, desc: 'SHA1 hash usage via hashlib.new' },
            // Cryptography library: weak ciphers
            { regex: /\b(?:DES|RC4|RC2|Blowfish)\b/g, desc: 'Weak encryption algorithm' },
            // pycryptodome: from Crypto.Cipher import DES / ARC4 etc.
            { regex: /from\s+Crypto\.Cipher\s+import\s+(?:DES|ARC4|ARC2|Blowfish)/g, desc: 'Weak encryption import from pycryptodome' },
        ],
        message: 'Weak cryptographic algorithm detected. Use stronger alternatives like SHA256 or AES-256.',
    },
];