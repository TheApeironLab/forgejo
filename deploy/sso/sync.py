"""Native Forgejo OIDC source and owned account projection.

Runs in the application's Pod with mounted credentials, never a Kubernetes token.
The init phase uses Forgejo's own migration/admin commands. The source secret and
owned recovery password hash use private database stdin, because v15's CLI only
accepts the client secret in argv and requires a terminal to change passwords.
All user changes use Forgejo's admin API over loopback, bound to source + subject.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

STATE = Path('/data/gitea/vasi-sso.json')
CONFIG = '/data/gitea/conf/app.ini'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(
    context=ssl.create_default_context(cafile='/etc/chentu-ca/ca.crt')))


def read(name, key):
    return (Path('/run/sso') / name / key).read_text().strip()


def http(url, body=None, token=None, basic=None, method=None, form=False):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if basic:
        headers['Authorization'] = 'Basic ' + base64.b64encode(basic.encode()).decode()
    data = None
    if body is not None:
        data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    with opener.open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=15) as response:
        data = response.read(4 * 1024 * 1024)
        return json.loads(data) if data else None


def command(args, stdin=None, env=None):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, env=env, timeout=180)
    if result.returncode:
        raise RuntimeError('private application command failed')
    return result.stdout


def sql(statement):
    host, _, port = os.environ['GITEA__database__HOST'].partition(':')
    env = dict(os.environ, PGPASSWORD=os.environ['GITEA__database__PASSWD'])
    return command(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-h', host, '-p', port or '5432',
                    '-U', os.environ['GITEA__database__USER'], '-d', os.environ['GITEA__database__NAME']], statement, env)


def literal(value):
    if '\x00' in value:
        raise ValueError('invalid database text')
    return "'" + value.replace("'", "''") + "'"


def save(state):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state)); temporary.chmod(0o600); temporary.replace(STATE)


def forgejo(*args, stdin=None):
    return command(['forgejo', '--work-path', '/data/gitea', '--custom-path', '/data/gitea',
                    '--config', CONFIG, *args], stdin)


def bootstrap():
    issuer, client = read('oidc', 'issuer'), read('oidc', 'client-id')
    identity = {'issuer': issuer, 'clientId': client}
    state = json.loads(STATE.read_text()) if STATE.exists() else None
    if state and state['identity'] != identity:
        raise RuntimeError('refusing to rebind persisted identities')
    Path(CONFIG).parent.mkdir(parents=True, exist_ok=True)
    Path('/data/git').mkdir(parents=True, exist_ok=True)
    command(['environment-to-ini', '--config', CONFIG])
    Path(CONFIG).chmod(0o600)
    forgejo('migrate')
    rows = json.loads(sql("SELECT coalesce(json_agg(row_to_json(s)), '[]') FROM login_source s WHERE name='keycloak';"))
    if rows and not state:
        raise RuntimeError('refusing to take over an existing login source')
    if not state:
        state = {'identity': identity, 'sourcePending': True}
        save(state)
    if not rows:
        forgejo('admin', 'auth', 'add-oauth', '--name', 'keycloak', '--provider', 'openidConnect',
                '--key', client, '--secret', 'configured-privately-before-web-starts',
                '--auto-discover-url', issuer + '/.well-known/openid-configuration',
                '--scopes', 'openid', '--scopes', 'profile', '--scopes', 'email',
                '--required-claim-name', 'roles', '--required-claim-value', 'git-user',
                '--group-claim-name', 'roles', '--admin-group', 'git-admin')
        rows = json.loads(sql("SELECT json_agg(row_to_json(s)) FROM login_source s WHERE name='keycloak';"))
    if len(rows) != 1 or rows[0]['type'] != 6:
        raise RuntimeError('ambiguous login source')
    source = rows[0]; cfg = json.loads(source['cfg'])
    if (cfg.get('ClientID') != client or cfg.get('Provider') != 'openidConnect'
            or cfg.get('OpenIDConnectAutoDiscoveryURL') != issuer + '/.well-known/openid-configuration'
            or (state.get('sourceId') is not None and state['sourceId'] != source['id'])):
        raise RuntimeError('login source ownership mismatch')
    cfg['ClientSecret'] = read('oidc', 'client-secret')
    # Source is quiescent during init. The secret is stdin to psql, never argv/output.
    sql('UPDATE login_source SET cfg=' + literal(json.dumps(cfg)) + ' WHERE id=' + str(int(source['id'])) + ';')
    state['sourceId'] = source['id']; state.pop('sourcePending', None); save(state)
    username = read('admin', 'username')
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', username):
        raise ValueError('invalid recovery username')
    email = 'recovery-' + hashlib.sha256((issuer + '\0' + client).encode()).hexdigest()[:32] + '@platform.invalid'
    users = json.loads(sql('SELECT coalesce(json_agg(row_to_json(u)), \'[]\') FROM "user" u WHERE lower_name=' + literal(username.lower()) + ';'))
    if users and (len(users) != 1 or not users[0]['is_admin'] or users[0]['login_type'] != 0 or users[0]['email'] != email):
        raise RuntimeError('refusing to overwrite a foreign recovery account')
    if not users:
        # The generated random password is captured and discarded privately.
        forgejo('admin', 'user', 'create', '--username', username, '--email', email,
                '--random-password', '--admin', '--must-change-password=false')
    # v15's password CLI requires a terminal (the newer stdin reader is not in
    # the pinned image). Store the documented PBKDF2 hash through private stdin.
    password = read('admin', 'password')
    current = json.loads(sql('SELECT json_agg(json_build_object(\'hash\',passwd,\'salt\',salt,\'algo\',passwd_hash_algo)) FROM "user" WHERE lower_name=' + literal(username.lower()) + ';'))[0]
    algorithm = 'pbkdf2$50000$50'
    matches = current['algo'] == algorithm and hmac.compare_digest(current['hash'],
        hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(current['salt']), 50000, 50).hex())
    if not matches:
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 50000, 50).hex()
        sql('UPDATE "user" SET passwd=' + literal(hashed) + ',salt=' + literal(salt) +
            ',passwd_hash_algo=' + literal(algorithm) + ',rands=' + literal(secrets.token_hex(16)) +
            ',must_change_password=false WHERE lower_name=' + literal(username.lower()) + ';')
    print('Code native login source and recovery account ready', flush=True)


def directory():
    deadline = time.monotonic() + 120
    def request(*args, **kwargs):
        if time.monotonic() >= deadline:
            raise TimeoutError("directory snapshot exceeded its deadline")
        return http(*args, **kwargs)
    issuer = read('directory', 'issuer')
    token = request(issuer + '/protocol/openid-connect/token', {
        'grant_type': 'client_credentials', 'client_id': read('directory', 'client-id'),
        'client_secret': read('directory', 'client-secret')}, form=True)['access_token']
    base = issuer.replace('/realms/', '/admin/realms/')
    def scan():
        count = request(base + '/users/count', token=token)
        if not isinstance(count, int) or not 0 <= count <= 100000:
            raise ValueError('invalid directory size')
        users = []
        for first in range(0, count, 100):
            page = request(base + '/users?' + urllib.parse.urlencode({'first': first, 'max': 100, 'briefRepresentation': 'false'}), token=token)
            if len(page) != min(100, count - first):
                raise RuntimeError('incomplete directory')
            users.extend(page)
        if len({u['id'] for u in users}) != count or request(base + '/users/count', token=token) != count:
            raise RuntimeError('directory changed during scan')
        result = []
        for user in users:
            if not user.get('enabled') or user.get('serviceAccountClientId'):
                continue
            roles = {r['name'] for r in request(base + '/users/' + urllib.parse.quote(user['id'], safe='') + '/role-mappings/realm/composite', token=token)}
            if 'git-user' not in roles or user.get('attributes', {}).get('tenant') != [os.environ['SSO_TENANT']]:
                continue
            result.append({'sub': user['id'], 'admin': 'git-admin' in roles})
        return sorted(result, key=lambda u: u['sub'])
    first, second = scan(), scan()
    if first != second:
        raise RuntimeError('directory changed during scan')
    return second


def sync():
    state = json.loads(STATE.read_text()); source = state['sourceId']
    if state['identity'] != {'issuer': read('oidc', 'issuer'), 'clientId': read('oidc', 'client-id')}:
        raise RuntimeError('persisted identity mismatch')
    credentials = read('admin', 'username') + ':' + read('admin', 'password')
    def api(path, body=None, method=None):
        return http('http://127.0.0.1:3000/api/v1' + path, body=body, basic=credentials, method=method)
    # Fetch a complete directory before making any account changes.
    wanted = directory()
    existing = []
    for page in range(1, 10001):
        users = api('/admin/users?' + urllib.parse.urlencode({'page': page, 'limit': 100}))
        existing.extend(users)
        if len(users) < 100:
            break
    else:
        raise RuntimeError('application account pagination exceeded')
    by_sub = {}
    for user in existing:
        if user.get('source_id') == source:
            sub = user.get('login_name')
            if not sub or sub in by_sub:
                raise RuntimeError('ambiguous application identity')
            by_sub[sub] = user
    wanted_ids = {u['sub'] for u in wanted}
    for sub, user in by_sub.items():
        if sub not in wanted_ids:
            api('/admin/users/' + urllib.parse.quote(user['login'], safe=''),
                {'active': False, 'prohibit_login': True, 'admin': False}, 'PATCH')
    for member in wanted:
        sub = member['sub']
        # Stable subject-derived local name prevents username/email account takeover.
        username = 'iam-' + hashlib.sha256((state['identity']['issuer'] + '\0' + sub).encode()).hexdigest()[:32]
        if sub not in by_sub:
            if any(u['login'].lower() == username for u in existing):
                raise RuntimeError('foreign local username collision')
            api('/admin/users', {'username': username, 'email': username + '@platform.invalid',
                'source_id': source, 'login_name': sub, 'must_change_password': False, 'send_notify': False}, 'POST')
        else:
            username = by_sub[sub]['login']
        api('/admin/users/' + urllib.parse.quote(username, safe=''),
            {'active': True, 'prohibit_login': False, 'admin': member['admin'], 'hide_email': True}, 'PATCH')


if __name__ == '__main__':
    if sys.argv[1:] == ['ready']:
        try:
            fresh = time.time() - Path('/tmp/sso-ready').stat().st_mtime < 120
        except OSError:
            fresh = False
        sys.exit(0 if fresh else 1)
    if len(sys.argv) == 2 and sys.argv[1] == 'bootstrap':
        try:
            bootstrap()
        except Exception as error:
            print('Code SSO bootstrap failed: ' + type(error).__name__, file=sys.stderr)
            sys.exit(1)
    else:
        while True:
            try:
                sync()
                Path('/tmp/sso-ready').touch()
            except Exception as error:
                Path('/tmp/sso-ready').unlink(missing_ok=True)
                print('Code SSO projection unavailable: ' + type(error).__name__, flush=True)
            time.sleep(10)
