import socket, hashlib, json, time, threading, os, re, codecs, urllib.parse
from flask import Flask, render_template, jsonify, request
from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

app = Flask(__name__)
DATA_FILE = os.path.join(os.path.dirname(__file__), 'data.json')

ROUTER_HOST = '192.168.1.1'
ROUTER_PORT = 80
ROUTER_USER = 'user'
ROUTER_PASS = 'user'

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwlo/vZBnSJ2MyJ0dbNcw
DvzPqBN+O/BPvLX93GIJVSZmquJHD9X6Xn6VYeM9mRKzjEbXPlv73Dj/gjjtNj9j
Tq2QVyW2Sd4ZkY9e3h1ALCCCfkbjnmSqedyrcvXriTeW+J65jhBje6lTJbafmC5q
bGiItjt0OeOkT+Vb4S7hYPSWIjeYYBh+7Y/fg25Rt2a+RgC8dahvJ3ttB1LHXADr
oCm6q7G+lpbRAlpC8jjc0rZdS0c6HcBoYgzW8vxjj2fTuFy3CZZTrpPyTv/C8K6B
hjTnjRe6ocgFVyQ0RIYfx2hxSJcuauR57OzfMzlgFQv3RAXguDZtuVUFLO2sAiwL
ELph3Acfy9Eh58SHcswZvsOSXY0JNb0XeRM9gxpntLRfM6TB7f9hYtYTDw5oKdyN
BY+nnEa/IpBUjndGDrSs3Z4BxRbYcJEwkKQZkvw/5TpQYbkD6sTRVSlZPaXSjeCl
0hsLCttqwJqRZcjbWXrINBYFw8PYE14Xr9BCyPgqocdQh7FgvasVgG6u5mLR1PBZ
o4EFF/LdY0yvMG5rl9egBk1XD/UMayhRtmSQEUzYt3eEWLBbqJB6MbVJ2ygcv5EL
ReDY0SWXw1PIEbHeP51A/MyB6kwSgZwdoQW3JiaPnGHMaE0NqfAYPNiGJLMsmvT/
rNUI/8iSCW+WvSzx9tByUxsCAwEAAQ==
-----END PUBLIC KEY-----"""

rsa_key = RSA.importKey(PUBLIC_KEY.encode())
rsa_cipher = PKCS1_v1_5.new(rsa_key)

DATA = {}
data_lock = threading.Lock()

def load_data():
    global DATA
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE) as f:
                DATA = json.load(f)
    except:
        DATA = {}
    DATA.setdefault('names', {})
    DATA.setdefault('schedules', {})

def save_data():
    with data_lock:
        with open(DATA_FILE, 'w') as f:
            json.dump(DATA, f, indent=2)

load_data()


class Router:
    def __init__(self):
        self.cookies = {}
        self.connected = False
        self.last_refresh = 0
        self.wlan_token = None

    def _req(self, method, path, body=None, headers=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ROUTER_HOST, ROUTER_PORT))

        req = f'{method} {path} HTTP/1.0\r\n'
        req += f'Host: {ROUTER_HOST}\r\n'
        req += 'User-Agent: Mozilla/5.0\r\n'
        if self.cookies:
            c = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
            req += f'Cookie: {c}\r\n'
        if headers:
            for hk, hv in headers.items():
                req += f'{hk}: {hv}\r\n'
        if body:
            if isinstance(body, str):
                body = body.encode()
            req += f'Content-Length: {len(body)}\r\n'
            req += 'Content-Type: application/x-www-form-urlencoded\r\n'
        req += '\r\n'

        s.sendall(req.encode() + body if body else req.encode())

        resp = b''
        while True:
            try:
                d = s.recv(65536)
                if not d:
                    break
                resp += d
            except socket.timeout:
                break
        s.close()

        hdr_part, _, http_data = resp.partition(b'\r\n\r\n')
        hdr_text = hdr_part.decode('latin-1')
        status = int(hdr_text.split(' ')[1])

        for line in hdr_text.split('\r\n'):
            if line.lower().startswith('set-cookie:'):
                for part in line[11:].split(';'):
                    if '=' in part:
                        kk, vv = part.split('=', 1)
                        self.cookies[kk.strip()] = vv.strip()

        return status, http_data.decode('latin-1')

    def login(self):
        try:
            self._req('GET', '/')
            _, b = self._req('GET', '/?_type=loginData&_tag=login_token')
            m = re.search(r'<ajax_response_xml_root[^>]*>(.*?)</ajax_response_xml_root>', b)
            if not m:
                return False
            token_xml = m.group(1)
            _, b = self._req('GET', '/?_type=loginData&_tag=login_entry')
            sess_token = json.loads(re.search(r'\{.*\}', b, re.DOTALL).group())['sess_token']
            pwd = hashlib.sha256(f'{ROUTER_PASS}{token_xml}'.encode()).hexdigest()
            self._req('POST', '/?_type=loginData&_tag=login_entry',
                      body=f'action=login&Username={ROUTER_USER}&Password={pwd}&Frm_Password={ROUTER_PASS}&_sessionTOKEN={sess_token}')
            _, b = self._req('GET', '/')
            if 'loginWrapper' in b:
                return False
            self._load_wlan()
            self.connected = True
            self.last_refresh = time.time()
            return True
        except Exception as e:
            print(f'login: {e}')
            return False

    def _load_wlan(self):
        _, b = self._req('GET', '/?_type=menuView&_tag=wlanAdvanced',
                         headers={'X-Requested-With': 'XMLHttpRequest'})
        m = re.search(r'_sessionTmpToken\s*=\s*"((?:\\x[0-9a-fA-F]{2})+)', b)
        if m:
            self.wlan_token = codecs.decode(m.group(1).encode().replace(b'\\x', b'\\x'), 'unicode_escape')
            return True
        m = re.search(r'_sessionTmpToken\s*=\s*"([^"]+)"', b)
        if m:
            self.wlan_token = m.group(1)
            return True
        return False

    def _ensure(self):
        if not self.connected:
            return self.login()
        return True

    def _post(self, raw_data):
        if not self.wlan_token:
            self._load_wlan()
        body = f'{raw_data}&_sessionTOKEN={self.wlan_token or ""}'
        digest = hashlib.sha256(body.encode()).hexdigest()
        check = b64encode(rsa_cipher.encrypt(digest.encode())).decode()
        s, b = self._req('POST', '/?_type=menuData&_tag=wlan_macfilterrule_lua.lua',
                         body=body,
                         headers={'X-Requested-With': 'XMLHttpRequest', 'Check': check})
        return s, b

    def _raw_rules(self):
        _, b = self._req('GET', '/?_type=menuData&_tag=wlan_macfilterrule_lua.lua',
                         headers={'X-Requested-With': 'XMLHttpRequest'})
        if 'SessionTimeout' in b:
            self._load_wlan()
            _, b = self._req('GET', '/?_type=menuData&_tag=wlan_macfilterrule_lua.lua',
                             headers={'X-Requested-With': 'XMLHttpRequest'})
        return b

    def get_devices(self):
        if not self._ensure():
            return []
        try:
            _, b = self._req('GET', '/?_type=hiddenData&_tag=accessdev_data&DeveiceType=ALL')
            devices = []
            for inst in re.findall(r'<Instance>(.*?)</Instance>', b, re.DOTALL):
                mac = re.search(r'MACAddress.*?<ParaValue>([^<]+)</ParaValue>', inst)
                host = re.search(r'HostName.*?<ParaValue>([^<]*)</ParaValue>', inst)
                ip = re.search(r'IPAddress.*?<ParaValue>([^<]*)</ParaValue>', inst)
                if mac:
                    devices.append({
                        'mac': mac.group(1).lower(),
                        'host': host.group(1) if host else 'Unknown',
                        'ip': ip.group(1) if ip else '-',
                    })
            return devices
        except:
            return []

    def get_acl_policy(self):
        if not self._ensure():
            return {}
        try:
            _, b = self._req('GET', '/?_type=menuData&_tag=wlan_macfilteraclpolicy_lua.lua',
                             headers={'X-Requested-With': 'XMLHttpRequest'})
            if 'SessionTimeout' in b:
                self._load_wlan()
                _, b = self._req('GET', '/?_type=menuData&_tag=wlan_macfilteraclpolicy_lua.lua',
                                 headers={'X-Requested-With': 'XMLHttpRequest'})
            policies = {}
            for inst in re.findall(r'<Instance>(.*?)</Instance>', b, re.DOTALL):
                aid = re.search(r'_InstID.*?<ParaValue>([^<]+)</ParaValue>', inst)
                pol = re.search(r'ACLPolicy.*?<ParaValue>([^<]+)</ParaValue>', inst)
                if aid and pol:
                    policies[aid.group(1)] = {'policy': pol.group(1)}
            return policies
        except:
            return {}

    def get_filter_rules(self):
        if not self._ensure():
            return []
        try:
            b = self._raw_rules()
            rules = []
            for inst in re.findall(r'<Instance>(.*?)</Instance>', b, re.DOTALL):
                iid = re.search(r'_InstID.*?<ParaValue>([^<]+)</ParaValue>', inst)
                mac = re.search(r'MACAddress.*?<ParaValue>([^<]+)</ParaValue>', inst)
                name = re.search(r'Name.*?<ParaValue>([^<]*)</ParaValue>', inst)
                iface = re.search(r'Interface.*?<ParaValue>([^<]+)</ParaValue>', inst)
                if iid and mac:
                    rules.append({
                        'id': iid.group(1),
                        'mac': mac.group(1).lower(),
                        'name': name.group(1) if name else '',
                        'interface': iface.group(1) if iface else '',
                    })
            return rules
        except:
            return []

    def toggle(self, mac, host, block):
        if not self._ensure():
            return False, 'Gagal login'
        try:
            mac = mac.lower()
            b = self._raw_rules()
            rules = []
            for inst in re.findall(r'<Instance>(.*?)</Instance>', b, re.DOTALL):
                iid = re.search(r'_InstID.*?<ParaValue>([^<]+)</ParaValue>', inst)
                m = re.search(r'MACAddress.*?<ParaValue>([^<]+)</ParaValue>', inst)
                if iid and m:
                    rules.append({'id': iid.group(1), 'mac': m.group(1).lower()})
            existing = next((r for r in rules if r['mac'] == mac), None)

            self._load_wlan()
            if not self.wlan_token:
                return False, 'Gagal token'

            if block:
                if existing:
                    return True, 'Sudah diblokir'
                parts = mac.split(':')
                name = host or f'Device_{parts[-1]}'
                mac_enc = urllib.parse.quote(mac)
                raw = (f'IF_ACTION=Apply'
                       f'&Name={name}'
                       f'&MACAddress={mac_enc}'
                       f'&sub_MACAddress0={parts[0]}&sub_MACAddress1={parts[1]}'
                       f'&sub_MACAddress2={parts[2]}&sub_MACAddress3={parts[3]}'
                       f'&sub_MACAddress4={parts[4]}&sub_MACAddress5={parts[5]}'
                       f'&Interface=DEV.WIFI.AP1&_InstID=')
            else:
                if not existing:
                    return True, 'Sudah tidak diblokir'
                raw = f'IF_ACTION=Delete&_InstID={existing["id"]}'

            s, resp = self._post(raw)
            if '<IF_ERRORID>0</IF_ERRORID>' in resp:
                return True, 'Diblokir' if block else 'Diizinkan'
            if 'SessionTimeout' in resp:
                self._load_wlan()
                if self.wlan_token:
                    s, resp = self._post(raw)
                    if '<IF_ERRORID>0</IF_ERRORID>' in resp:
                        return True, 'Diblokir' if block else 'Diizinkan'
            return False, f'Gagal (err:{resp[:100]})'
        except Exception as e:
            return False, f'Error: {e}'


router = Router()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    devices = router.get_devices()
    policies = router.get_acl_policy()
    rules = router.get_filter_rules()

    with data_lock:
        names = dict(DATA.get('names', {}))
        schedules = dict(DATA.get('schedules', {}))

    blocked = {r['mac'] for r in rules}
    seen = set()
    pol = policies.get('DEV.WIFI.AP1', {}).get('policy', 'Disabled')

    for d in devices:
        m = d['mac']
        d['blocked'] = m in blocked
        d['name'] = names.get(m, d['host'])
        d['schedule'] = schedules.get(m, {})
        seen.add(m)

    for r2 in rules:
        m = r2['mac']
        if m not in seen:
            devices.append({
                'mac': m, 'host': r2['name'] or 'Device',
                'name': names.get(m, r2['name'] or 'Device'),
                'ip': '-', 'blocked': True,
                'schedule': schedules.get(m, {}),
            })

    return jsonify({
        'connected': router.connected,
        'ssid1_policy': pol,
        'devices': devices,
        'blacklist_count': len(rules),
    })


@app.route('/api/toggle')
def api_toggle():
    mac = request.args.get('mac', '').strip().lower()
    host = request.args.get('host', 'Device')
    action = request.args.get('action', 'block')
    if not mac or not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
        return jsonify({'success': False, 'message': 'MAC invalid'})
    ok, msg = router.toggle(mac, host, action == 'block')
    return jsonify({'success': ok, 'message': msg})


@app.route('/api/rename', methods=['POST'])
def api_rename():
    data = request.get_json()
    mac = data.get('mac', '').strip().lower()
    name = data.get('name', '').strip()
    if not mac or not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
        return jsonify({'success': False, 'message': 'MAC invalid'})
    with data_lock:
        DATA.setdefault('names', {})
        if name:
            DATA['names'][mac] = name
        else:
            DATA['names'].pop(mac, None)
        save_data()
    return jsonify({'success': True})


@app.route('/api/schedule', methods=['POST'])
def api_schedule():
    data = request.get_json()
    mac = data.get('mac', '').strip().lower()
    enabled = data.get('enabled', False)
    block_time = data.get('block_time', '')
    unblock_time = data.get('unblock_time', '')
    days = data.get('days', [0, 1, 2, 3, 4, 5, 6])
    if not mac or not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
        return jsonify({'success': False, 'message': 'MAC invalid'})
    with data_lock:
        DATA.setdefault('schedules', {})
        if enabled and block_time and unblock_time:
            DATA['schedules'][mac] = {
                'enabled': True, 'block_time': block_time,
                'unblock_time': unblock_time, 'days': days,
            }
        else:
            DATA['schedules'].pop(mac, None)
        save_data()
    return jsonify({'success': True})


@app.route('/api/login')
def api_login():
    return jsonify({'connected': router.login()})


@app.route('/api/refresh')
def api_refresh():
    router.connected = False
    return jsonify({'connected': router.login()})


def scheduler():
    while True:
        time.sleep(30)
        try:
            with data_lock:
                scheds = dict(DATA.get('schedules', {}))
            now = time.localtime()
            cur = now.tm_hour * 60 + now.tm_min
            wday = now.tm_wday

            for mac, s in scheds.items():
                if not s.get('enabled'):
                    continue
                if wday not in s.get('days', list(range(7))):
                    continue
                bt = s.get('block_time', '')
                ut = s.get('unblock_time', '')
                if not bt or not ut or ':' not in bt or ':' not in ut:
                    continue
                bp = int(bt.split(':')[0]) * 60 + int(bt.split(':')[1])
                up = int(ut.split(':')[0]) * 60 + int(ut.split(':')[1])
                rules = router.get_filter_rules()
                is_blocked = any(r['mac'] == mac for r in rules)
                should = (bp <= cur < up) if bp < up else (cur >= bp or cur < up)
                if should and not is_blocked:
                    print(f'sched: block {mac}')
                    router.toggle(mac, '', True)
                elif not should and is_blocked:
                    print(f'sched: unblock {mac}')
                    router.toggle(mac, '', False)
        except Exception as e:
            print(f'sched err: {e}')


threading.Thread(target=scheduler, daemon=True).start()

if __name__ == '__main__':
    print('Connecting...')
    if router.login():
        print(f'OK: {len(router.get_devices())} devices, {len(router.get_filter_rules())} rules')
    else:
        print('FAILED')
    app.run(host='0.0.0.0', port=5000, debug=True)
