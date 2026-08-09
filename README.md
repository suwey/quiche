# Anywhere



## A rust client for router.

1. Real BoringSsl fingerprint.
2. Socks5 inbound. most platform can use it.
3. Simple quic with auth inbound & outbound.

```
cargo build -p anywhere
RUST_LOG=debug cargo run -p anywhere --bin anywhere -- -c anywhere/config/server.toml
RUST_LOG=debug cargo run -p anywhere --bin anywhere -- -c anywhere/config/quiche-client.toml
```

4. Anytls outbound with multiplex, one tls multi stream.

```
cargo build -p anywhere
# fill your server info in anytls-client.toml
RUST_LOG=debug cargo run -p anywhere --bin anywhere -- -c anywhere/config/anytls-client.toml
```

Set socks5://127.0.0.1:1080 and test.

5. Implemented useful clash api for [MetaCudeXD](https://github.com/MetaCubeX/metacubexd/releases/): most info APIs, global mode change (auto disable tun forward when mode direct, enable tun when mode rule/global), `Restart Core` by start command setted by -s option (not set will execve a new process, if set to systemctl will execute command: systemctl restart [exename]), `Reload Config` is same as restart, `Upload Config` / `Edit Config` / `Pull Config` will overwrite config file and restart. 

6. Urltest outbound as auto selector, domain and geo rules, tun inbound (linux/windows/macos/android).
7. Fake ip, DNS hijack auto enabled by tun inbound, DOH support.
8. Auto monitor wan ifaces and bypass lan ifaces.
9. Vless outbound, tls + ws mode for [edgetunnel](https://github.com/cmliu/edgetunnel), hide sensitive characters and back up as `deploy/openclaw`, can deploy to cloudflare pages (workers domain has been blocked).
10. Mless outbound, my multiplex protocol based on vless, deploy `deploy/hermes` to cloudflare workers:
```
cd anywehre/deploy/hermes
npm install -g wrangler
# login to cloudflare
wrangler login
npm install
npm run deploy
# set login password
npx wrangler secret put ADMIN
# deploy again after change env
npm run deploy
```
Add a custom.domain.not.blocked to worker in cloudflare dashboard, then login at https://custom.domain.not.blocked/login, config is same as vless, only type is `mless`:
```
[[outbounds]]
type = "mless"
tag = "CF"
# copy and open url https://custom.domain.not.blocked/sub?token=xxxxxxxxxxxxx after login
# pick one from urls like vless://xxxx-xxx-xx-xx@s.s.s.s:1334?......
# if blocked, change to another one
server = "s.s.s.s:1334"
password = "xxxx-xxx-xx-xx"
sni = "custom.domain.not.blocked"
fp = true

[outbounds.transport]
type = "ws"

[outbounds.transport.ws]
path = "/"
headers = { Host = "custom.domain.not.blocked" }

# default 5 connections is enough for 4k 60fps video
# since cloudflare's network keep changing, may need adjust this
[outbounds.xmux]
pool_size = 5
```
Recommend to deploy `openclaw` and `hermes` both, one for `vless/ss/trojan` one for `mless` then cloudflare's free plan will be very enough to use. Many thanks to @cmliu for [edgetunnel](https://github.com/cmliu/edgetunnel), see it for more info.

11. SS 2022 outbound:
```
[[outbounds]]
type = "shadowsocks"
tag = "ss"
server = "V.z.t:3"
method = "2022-blake3-aes-128-gcm"
password = "jgjhkhkkhnknknk==:gjhbkhkhkkhii=="
plugin = "obfs-local"
plugin_opts = "obfs=http;obfs-host=os.i.a.com"
```

12. Add `--sub` to convert clash subscription to `sub.toml`, copy what you need and change [config.toml](./anywhere/deploy/koolshare/config.toml) and start to use.

## Deploy to arm64 router running koolshare with jffs enabled
Tun inbound only support linux now and need ip & iptables commands (as root), other platform will just ignore it, config is very simple and most are setted, linux desktop can use too, see [config.toml](./anywhere/deploy/koolshare/config.toml), build for arm64 router:
```
cargo zigbuild -p anywhere --target aarch64-unknown-linux-musl --release
```

1. On router:
```
mkdir -p /jffs/anywhere/ui
```
2. Download [MetaCudeXD](https://github.com/MetaCubeX/metacubexd/releases/) and extract (or my version), anywhere release and files in deploy, change your settings in config.toml.
```
scp -O -r compressed-dist/* 192.168.1.1:/jffs/anywhere/ui/
scp -O anywhere 192.168.1.1:/jffs/anywhere/
scp -O anywhere.sh 192.168.1.1:/jffs/anywhere/
scp -O config.toml 192.168.1.1:/jffs/anywhere/
scp -O S99anywhere.sh 192.168.1.1:/koolshare/init.d/
```
3. On router:
```
cd /jffs/anywhere && chmod +x anywhere*
./anywhere.sh start
```
Confirm works fine before reboot, if can't work, ctrl+c or ./anywhere.sh stop, check config.toml and try again. If really can not work, `rm -rf /koolshare/init.d/S99anywhere.sh` then reboot.

4. Open UI at http://192.168.1.1:9090 to see infos, can change mode to drect or rule/global or restart core in config page.


## Notice
1. S99anywhere.sh will delay 30s to start anywhere for original routes complete in router.
2. Power cycling may cause issue.
3. Full tested on AC86U, only ipv4 enabled.


## Android
Install apk, click start button, click `Open Web UI` (or open in computer on same local network), then go to config page: upload or edit [anywhere.toml](./anywhere-android/app/src/main/assets/config/anywhere.toml), it will restart.


`bash scripts/build.sh --apk` to build apk, see prerequisites in [build_on_mac.sh](./scripts/build_on_mac.sh).

## Windows
Download [wintun](https://www.wintun.net), copy your platform's `wintun.dll` to same dir with `anywhere.exe` and [start.bat](./anywhere/deploy/windows/start.bat), right click `start.bat` and run as admin to use tun mode.


## Some service provider not support or limit speed of third party client
Since all platform have ssh, use SSH outbound make router connect back to mac or win computer running provider's client.
1. Make sure provider's client running and works, then find out their local port, on mac computer:
```
// windows: netsh winhttp show proxy
scutil --proxy
<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 6518
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 6518
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 1
  SOCKSPort : 6518
  SOCKSProxy : 127.0.0.1
}
```
Remember HTTPPort 6518.

2. Make router can ssh to mac without password, on AC86U:
```
dropbearkey -t ed25519 -f /jffs/anywhere/id_dropbear
Public key portion is:
ssh-ed25519 AAAA...
Fingerprint: SHA256:j1k9r1...
```
Copy the line start with ssh-ed25519 and add to mac's `.ssh/authorized_keys`, confirm can ssh to mac from router without password.

4. Add a SSH outbound in config.toml and set urltest to it:
```
[[outbounds]]
type = "ssh"
tag = "mac"
cmd = "ssh -o ExitOnForwardFailure=yes -K 10 -i /jffs/anywhere/id_dropbear -N -L {PORT}:127.0.0.1:6518 192.168.1.30"
server = "127.0.0.1:{PORT}"

[[outbounds]]
type = "urltest"
tag = "auto"
outbounds = ["mac"]
```
Make sure the port 6518 is right, the ip addr of mac is right, can run this on router:
```
ssh -o ExitOnForwardFailure=yes -K 10 -i /jffs/anywhere/id_dropbear -N -L 1080:127.0.0.1:6518 192.168.1.30
```
Then test with:
```
wget -e use_proxy=yes -e http_proxy=http://127.0.0.1:1080 -e https_proxy=http://127.0.0.1:1080 -qO- ip.sb
```

5. Backup config.toml and scp new config to router, then:
```
cd /jffs/anywhere
./anywhere.sh restart
```
Open your phone or TV see if works, not recommend reboot router because provider's client may not stable, just use it this way since you must keep computer running. Mac will temporary can't visit outside in my test, maybe caused by provider's client concurrent limit, other provider's client not tested.

6. If your router's ssh is open-ssh version, use `ssh-keygen` in step 2 and `-o ServerAliveInterval=10` instead of `-K 10` in ssh cmd.