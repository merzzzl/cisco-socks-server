# LAN Client Autodiscovery & Network Change Tracking

## Overview

Сейчас доступность прокси из LAN держится на статической паре `lan_clients: {ip, mac}` в `~/.cisco-socks5.yaml` и на снимке LAN-интерфейса, который снимается один раз до первого коннекта. При смене сети (другой Wi‑Fi, другой роутер) ломаются все три опоры:

| Что | Где задано | Почему ломается |
|---|---|---|
| IP клиента | `lan_clients[].ip` | DHCP новой сети выдаёт другой адрес |
| MAC клиента | `lan_clients[].mac` | клиент использует частный (рандомизированный, ротируемый) Wi‑Fi MAC |
| LAN-интерфейс/подсеть мака | снимок в `detectLAN` | никогда не обновляется после первого успеха — нужен рестарт |

Цель: прокси должен оставаться доступным из LAN после смены сети **без правки конфига и без рестарта**. `lan_clients` становится необязательным пред-заполнением.

Побочное требование, которое появляется вместе с автообнаружением: прокси не должен становиться открытым входом в корпоративную сеть для любого соседа по Wi‑Fi, и не должен выпускать трафик мимо туннеля, пока VPN не поднят.

## Context (from discovery)

### Диагностика (2026-10-15/16)

- После коннекта Cisco маршрутизирует всю подсеть LAN в туннель: `192.168.0  link#11  UCS  utun4` (раньше было `192.168.0.0/16 → utun4`). Host-пины `192.168.0.214 → en0` Cisco терпит (`UHLS en0`).
- В конфиге был `f4:d4:88:85:75:6f`, но ядро само выучило по ARP `12:49:61:d3:72:48` (бит locally-administered → частный адрес). Пиннер каждую секунду считал это дрейфом и перезаписывал рабочую запись устаревшим MAC → ответы уходили несуществующему устройству. Лог: `LAN client pinned` каждую секунду + периодические `arp -S ... cannot intuit interface index` (в моменты, когда Cisco успевал снести host-запись).
- Через ночь у того же клиента MAC снова сменился: `82:b4:3b:8e:d2:f3` — т.е. MAC ротируется, статический MAC в конфиге в принципе не жизнеспособен.
- После исправления MAC в конфиге: ARP стабилен, tcpdump показал полный handshake `SYN → SYN-ACK → ACK`, т.е. L2/L3-путь работает. Клиент сразу после ACK шлёт `FIN` без данных. ~~Отдельная проблема на стороне клиента~~ — **объяснено**: это проба доступности шлюза в twarp (`internal/app/status.go:checkGateway` делает `Dial` + `Close` без SOCKS-приветствия; TUI вызывает её каждые 5 с, `twarp status` — на каждый запуск). Не баг; в twarp-плане `20261016-twarpd-no-sudo.md` проба переводится на SOCKS5-рукопожатие.
- Ключевой факт для дизайна: клиент перед первым SYN шлёт ARP-запрос на IP мака, поэтому к моменту `Accept` ядро мака уже знает **актуальный** MAC клиента (`arp -n <ip>` → `on en0`).
- Сейчас LAN-листенер принимает соединения от любого хоста, но ответы доходят только до запиненных `lan_clients` (остальным уходят на MAC шлюза). То есть пиннинг де-факто работает как allowlist. Автообнаружение этот allowlist убирает (см. Solution Overview, п. 4).
- Пока Cisco в `Reconnecting`/`Disconnected`, листенеры продолжают принимать новые CONNECT и dial'ят по текущей таблице маршрутов, т.е. мимо туннеля. `dropConnsOnVPNLoss` закрывает только уже открытые соединения.

### Связка с twarp

Основной LAN-клиент — машина с twarp: sing-box outbound `gateway` = `socks` на `<мак>:8080`. Что из этого следует для этого плана:

- twarp-сторона (план twarpd) сама находит **прокси-хост** при смене сети по `.local`-имени; этот план находит **клиента** через ARP. Вместе обе стороны переживают смену сети без правки конфигов.
- LAN-листенер только `tcp4` (`IP_BOUND_IF`). twarp выбирает IPv4-адрес прокси-хоста; IPv6 к нам не подключится.
- Периодическая проба twarp (TCP/SOCKS-рукопожатие каждые 5 с из TUI) — полезный keepalive: каждое соединение обновляет `LastSeen` клиента в реестре и заново учит ядро мака MAC клиента. Проба не должна делать CONNECT, иначе спамит лог `connection to …`.
- Корпоративный DNS twarp ходит через нас по TCP (`{type: tcp, detour: gateway}`), а этот репо исходит из того, что DNS за туннелем принимает только UDP (поэтому `startDNS` — TCP→UDP). Нужно проверить на живом VPN (Post-Completion); если TCP не работает — отдельная задача на LAN-доступ к нашему DNS-форвардеру, вне скоупа этого плана.
- Формат логов о смене адреса одинаковый на обеих сторонах: `old=… new=…`.

### Файлы

- `internal/service/service.go` — `LANClient`, `State`, `startPinner` (сейчас стартует только при непустом `lan_clients`)
- `internal/service/proxy.go` — `proxyListeners`, `acceptConns` (LAN-листенер с `IP_BOUND_IF`, `net.ErrClosed` = фатально), `connTracker`
- `internal/service/cisco.go` — `detectLAN` (снимок один раз), supervisor tick
- `internal/utils/route/route.go` — `DetectLAN`, `EnsureClientPinned`, `arpEntryMatches`, `normalizeMAC`
- `cmd/config.go` — валидация `lan_clients` (сейчас `mac` обязателен)
- `internal/utils/tui/status.go` — отображение bind-интерфейса

### Паттерны

- Мутация состояния только через `setStatus(func(*State))`; периодические циклы — через `sleepCtx`; все ожидания `ciscoReady` селектят `ctx.Done()`.
- Shell-out'ы через `shell.Run`; чистые парсеры покрыты тестами (`route_test.go`).
- Проверка пина read-only (`arp -n`), мутация (`arp -S`) — только при дрейфе: безусловный `arp -S` рвёт in-flight кадры.

## Development Approach

- **testing approach**: Regular (code first, then tests). Тестами покрывается только чистый код (парсеры, реестр клиентов, логика решения «adopt/repin», тик пиннера с подменёнными shell-операциями) — остальное требует root и живого VPN, как и во всём репо.
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run `make test` and `make vet` after each change
- maintain backward compatibility: существующий конфиг с `lan_clients: {ip, mac}` и без новых ключей продолжает работать как раньше (без auth, без автообнаружения)

## Testing Strategy

- **unit tests**: парсер ARP-вывода, `DecidePin`, реестр клиентов (add/expire/reset/snapshot, пропуск живых IP), тик пиннера на фейковых `lookup`/`pin`, `lanChanged` + дебаунс, решение «нужно ли обновлять клиента», валидация конфига (необязательный `mac`, пара `socks_user`/`socks_password`, `lan_discovery`), VPN-гейт CONNECT.
- **e2e tests**: в проекте нет; ручная проверка — в Post-Completion.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope

## Solution Overview

Выбрана комбинация механизмов:

1. **Автообнаружение клиентов (основной).** На каждый `Accept` на LAN-листенере берём IP пира, проверяем, что он в LAN-подсети, читаем его MAC из `arp -n` (ядро уже выучило его из ARP-запроса клиента) и регистрируем в реестре пиннера. Конфиг не нужен. Включается только при выполнении п. 4.
2. **MAC из ARP, а не из конфига (fallback для `lan_clients`).** Если в ARP есть запись для клиента **на правильном интерфейсе**, но с другим MAC — пиннер не перебивает её, а принимает новый MAC (Warn «LAN client MAC changed»). Перепин (`route change` + `arp -S`) — только если записи нет или она ушла на чужой интерфейс (`utun*`). Это лечит ротацию частного MAC и для статических, и для обнаруженных клиентов. `mac` в конфиге становится необязательной подсказкой.
3. **Отслеживание смены сети.** На каждом tick supervisor'а перепроверяем LAN-интерфейс и подсеть. Изменение применяется после подтверждения на двух тиках подряд: обновляем `State`, сбрасываем обнаруженных клиентов (у статических — MAC), переоткрываем LAN-листенер на новом интерфейсе (без рестарта процесса).
4. **Аутентификация на LAN-листенере.** Необязательные `socks_user`/`socks_password` в конфиге; если заданы, LAN-листенер требует SOCKS5 username/password (RFC 1929), loopback остаётся без auth. Автообнаружение (п. 1) включается, только если auth задан, либо явным `lan_discovery: true` (пользователь принимает риск открытого прокси в любой сети). Без того и другого поведение как сейчас: пинятся только `lan_clients`. На стороне twarp — креды в `secrets.yaml` для outbound `gateway` (twarp-план).
5. **VPN-гейт для CONNECT.** Пока `CiscoConnected == false`, CONNECT отклоняется ответом `network unreachable` (0x03) — без dial мимо туннеля. sing-box на клиенте падает сразу, а не по таймауту.

Отвергнуто:
- Только вариант 2 — IP всё равно пришлось бы вписывать руками.
- Резервация DHCP / отключение частного MAC на клиенте — работает, но надо делать в каждой новой сети заново.
- mDNS/hostname клиента — DNS под Cisco идёт через туннель, лишняя сложность.
- Allowlist по MAC/IP вместо auth — MAC ротируется, IP меняется с сетью; это ровно то, от чего план уходит.
- Закрывать листенеры на время реконнекта вместо VPN-гейта — клиент получает `connection refused` вместо понятного SOCKS-ответа, а владелец листенера усложняется.

Компромисс: принятие MAC из ARP доверяет LAN (ARP-спуфинг из локалки может перенаправить ответы прокси). С auth это даёт отказ в обслуживании, но не доступ в корпоративную сеть; без auth (`lan_discovery: true`) — осознанно принятый риск.

## Technical Details

### ARP-парсер (`route`)

```go
// ArpEntry — результат `arp -n <ip>`.
type ArpEntry struct {
    MAC   string // нормализованный
    Iface string
}

func parseArpEntry(out string) (ArpEntry, bool) // false для "-- no entry" / "(incomplete)"
func LookupARP(ctx context.Context, ip string) (ArpEntry, bool)
func Pin(ctx context.Context, ip, mac, iface string) error // route change + arp -S ... temp
```

`EnsureClientPinned` и `arpEntryMatches` удаляются: их заменяют `LookupARP` + `DecidePin` + `Pin`, оркестрация — в пиннере.

### Решение пиннера (чистая функция, экспортируется из `route`)

```go
type PinAction int // PinNone | PinAdopt | PinRepin

func DecidePin(entry ArpEntry, found bool, wantMAC, iface string) PinAction
```

- `found && entry.Iface == iface && MAC совпадает` → `PinNone`
- `found && entry.Iface == iface && MAC другой или wantMAC пуст` → `PinAdopt` (обновить MAC в реестре, Warn, без мутаций ARP)
- `wantMAC == ""` и записи нет **или она на чужом интерфейсе** → `PinNone` (пинить нечем; ждём, пока клиент сам появится в ARP)
- иначе → `PinRepin`

### Реестр клиентов (`service/clients.go`)

```go
type clientEntry struct {
    MAC      string
    Static   bool      // из lan_clients — не истекает
    LastSeen time.Time // обновляется хуком Accept
}

type clientRegistry struct {
    mu      sync.Mutex
    clients map[string]*clientEntry // key: IP
}

func newClientRegistry(static []LANClient) *clientRegistry
func (r *clientRegistry) seen(ip, mac string, now time.Time) (isNew bool) // пустой mac не затирает известный
func (r *clientRegistry) lookup(ip string) (mac string, lastSeen time.Time, ok bool)
func (r *clientRegistry) setMAC(ip, mac string)
func (r *clientRegistry) snapshot() map[string]string // ip → mac, копия
func (r *clientRegistry) expire(now time.Time, ttl time.Duration, live map[string]bool) []string
func (r *clientRegistry) resetNetwork() // удалить обнаруженных, у статических сбросить MAC в ""
```

- TTL обнаруженных клиентов: `discoveredClientTTL = 30 * time.Minute` от `LastSeen`. `expire` пропускает IP, у которых есть живые соединения (`live` = `connTracker.remoteIPs()`), поэтому долгая SSH-сессия не теряет пин посреди работы. Для этого `connTracker` переезжает в `Service` (создаётся в `New`).
- `resetNetwork` при смене сети: статическая запись из домашней сети не должна в чужой сети делать `arp -S` на устаревший MAC (это отобрало бы IP у его нового владельца). MAC статики после сброса заново подхватывается через `PinAdopt`.

### Пиннер (`service.go`)

- `startPinner` запускается всегда (не только при непустом `lan_clients`).
- Тик — метод над подменяемыми операциями, чтобы покрыть его тестами без root:

  ```go
  type pinOps struct {
      lookup func(ctx context.Context, ip string) (route.ArpEntry, bool)
      pin    func(ctx context.Context, ip, mac, iface string) error
  }

  func (s *Service) pinClients(ctx context.Context, ops pinOps, st State)
  ```

- Пинятся только IP, входящие в текущую `State.LANSubnet` (статика из другой сети пропускается).
- `PinAdopt` → `registry.setMAC` + `slog.Warn("LAN client MAC changed", "ip", …, "old", …, "new", …)`.
- `PinRepin` → `ops.pin`; Info «LAN client pinned» при успехе, Debug при ошибке (как сейчас).
- `expire` — по времени, раз в `clientExpireInterval = time.Minute`; Info «LAN client expired».

### Хук в Accept (`proxy.go`)

`acceptConns` становится методом `Service` с флагом `lan bool`; `connTracker.add(conn, lan)` помечает, с какого листенера соединение. Для LAN-соединений, если автообнаружение включено, в горутине соединения до `ServeConn`:

1. `remote := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()`
2. `State.LANSubnet.Contains(remote)`, иначе выход
3. троттлинг (чистая `needsRefresh(known bool, mac string, lastSeen, now time.Time) bool`): lookup делается, если IP неизвестен, **или его MAC пуст**, или `LastSeen` старше `clientRefreshInterval = time.Minute`
4. `route.LookupARP(ctx, ip)` — если запись на `State.LANInterface`, берём её MAC, иначе `""`
5. `registry.seen(ip, mac, now)`; Info «LAN client discovered» только для новых IP

Синхронный `arp -n` в Accept-петле недопустим — поэтому хук в горутине соединения.

### LAN-снимок и смена сети

- `State.LANSubnet` становится `netip.Prefix` (сравнимое значение с `Contains`, безопасно копируется в `GetState`); `route.DetectLAN` возвращает `(netip.Prefix, string, error)`.
- `type lanSnapshot struct { Iface string; Subnet netip.Prefix }` — сравнимый.
- `detectLAN` выполняется на каждом tick. После коннекта default через `en0` остаётся в таблице (`default 192.168.0.1 UGScIg en0`), поэтому детект работает и при поднятом VPN.
- Fallback `scanRFC1918` предпочитает текущий `State.LANInterface`, если на нём ещё есть RFC1918-адрес (чтобы при пропаже non-tunnel default не перескочить на `bridge100`/`en5`).
- Чистая `lanChanged(cur, next lanSnapshot) bool`: `next.Iface != "" && next != cur`. Переход «найдено → не найдено» игнорируется — остаётся последний снимок.
- Дебаунс: при `cur` непустом новый снимок применяется, только если совпал на двух тиках подряд (`pendingLAN` в `ciscoSupervisor`). Первый детект (пусто → найдено) применяется сразу.
- При применении:
  - `setStatus`: новые `LANInterface`/`LANSubnet`
  - `registry.resetNetwork()`
  - неблокирующая отправка в `lanCheck chan struct{}` (буфер 1)
  - Info `LAN changed old=en0/192.168.0.0/24 new=en1/10.0.0.0/24` (первый детект — как сейчас, `LAN detected`)
- Сигнал означает «проверь», а не «изменилось»: владелец LAN-листенера в `startProxy` хранит снимок, под который открыт листенер, и переоткрывает только при расхождении с `State` (иначе сигнал от первого детекта, лежащий в буфере, переоткрывал бы листенер сразу после старта).
- Владелец LAN-листенера:
  - на каждый листенер — свой `context`; намеренное закрытие = отмена этого контекста + `Close`, и `acceptConns` возвращается без ошибки; неожиданный `net.ErrClosed` по-прежнему фатален
  - при переоткрытии: закрыть старый листенер, `connTracker.closeLAN()`, открыть `listenBoundToInterface` на новом интерфейсе (Go ставит `SO_REUSEADDR`, повторный bind на `:8080` проходит сразу)
  - если bind не удался — повтор раз в `lanRetryInterval = 10 * time.Second`, а не ожидание следующей смены сети
  - если LAN не найден при старте — loopback работает, LAN-листенер откроется по сигналу
  - loopback-листенер не трогается
- Cisco сам переподключается при смене сети; `PFDisabled` уже сбрасывается на `Reconnecting/Disconnected` — менять не нужно.

### Аутентификация и включение автообнаружения

- Конфиг: `socks_user`, `socks_password` — оба или ни одного; `lan_discovery: bool` (по умолчанию `false`).
- `discoveryEnabled = auth задан || lan_discovery`. При `lan_discovery: true` без auth — `slog.Warn` при старте: «LAN proxy is open to anyone on the network».
- Два `socks5.Server`: для loopback без auth, для LAN — с `socks5.WithCredential(socks5.StaticCredentials{user: password})` (если auth задан). Middleware/логгер общие.
- Без auth и без `lan_discovery` хук Accept не регистрирует клиентов — пинятся только `lan_clients`, как сейчас.

### VPN-гейт CONNECT

- Проверено по исходникам go-socks5 v0.0.6 (`handle.go`): ошибка из `WithConnectMiddleware` reply **не** отправляет (клиент видит обрыв), а FQDN назначения резолвится **до** middleware — через системный резолвер, т.е. через наш `127.0.0.1:53` и `dns_servers`, которые без туннеля уходят по обычному default.
- Поэтому гейт в двух местах, оба на одной проверке `GetState().CiscoConnected`:
  - `WithResolver`: обёртка над `socks5.DNSResolver`, без VPN возвращает ошибку → go-socks5 сам шлёт `RepHostUnreachable`, имя никуда не резолвится;
  - connect-middleware: без VPN сам вызывает `socks5.SendReply(w, statute.RepNetworkUnreachable, nil)` и возвращает ошибку (для IP-назначений, где резолва нет).
- Гейт действует на оба листенера (loopback тоже не должен ходить мимо туннеля).
- `startDNS` без VPN так же форвардит в `dns_servers` мимо туннеля — та же утечка, но в другом подсистеме; ➕ вне скоупа, отдельная задача.

### Конфиг

- `lan_clients[].mac` — необязательный (валидируется только если задан).
- `lan_clients` целиком — необязательный (и так был).
- `socks_user`/`socks_password` — необязательные, только парой; `lan_discovery` — необязательный.

## What Goes Where

- **Implementation Steps** — код, тесты, документация в этом репо.
- **Post-Completion** — ручная проверка на живом VPN со сменой сети и с twarp-клиентом.

## Implementation Steps

### Task 1: ARP-парсер, DecidePin и Pin

**Files:**
- Modify: `internal/utils/route/route.go`
- Modify: `internal/utils/route/route_test.go`

- [x] добавить `ArpEntry`, `parseArpEntry`, `LookupARP` (через `shell.Run`)
- [x] выделить `Pin(ctx, ip, mac, iface) error` (`route change` + `arp -S ... temp`); удалить `EnsureClientPinned` и `arpEntryMatches`
- [x] добавить экспортируемые `PinAction` (`PinNone`/`PinAdopt`/`PinRepin`) и `DecidePin`
- [x] тесты `parseArpEntry`: обычная запись, `permanent`, `-- no entry`, `(incomplete)`, MAC без ведущих нулей, запись на `utun4`
- [x] тесты `DecidePin`: none / adopt (другой MAC на том же iface; пустой wantMAC на том же iface) / repin (нет записи, чужой iface) / none без MAC (нет записи; запись на `utun4`)
- [x] `make test` — должно пройти

### Task 2: Реестр клиентов

**Files:**
- Create: `internal/service/clients.go`
- Create: `internal/service/clients_test.go`

- [x] реализовать `clientRegistry` (`seen`, `lookup`, `setMAC`, `snapshot`, `expire`, `resetNetwork`)
- [x] конструктор из `[]LANClient` (статические записи)
- [x] тесты: статические не истекают; `resetNetwork` удаляет обнаруженных и сбрасывает MAC статических; обнаруженные истекают по TTL; IP из `live` не истекает; `seen` обновляет `LastSeen`, пустой MAC не затирает известный; `snapshot` — копия
- [x] `make test` — должно пройти

### Task 3: Пиннер поверх реестра + adopt MAC

**Files:**
- Modify: `internal/service/service.go`
- Modify: `internal/service/proxy.go` (`connTracker` в `Service`, метка `lan`, `remoteIPs`, `closeLAN`)

- [x] `Service` держит `*clientRegistry` и `*connTracker` вместо `[]LANClient`
- [x] `startPinner` запускается всегда; тик `pinClients(ctx, ops, state)` над `LookupARP` + `DecidePin` + `Pin`
- [x] пропуск IP вне `State.LANSubnet`
- [x] `PinAdopt` → `registry.setMAC` + Warn `old=… new=…`, без мутации ARP
- [x] `PinRepin` → `Pin`; Info при успехе, Debug при ошибке
- [x] раз в минуту `registry.expire(now, ttl, tracker.remoteIPs())`, Info «LAN client expired»
- [x] тесты на фейковых `pinOps`: adopt обновляет реестр и не вызывает `pin`; repin вызывает `pin` с известным MAC; пустой MAC без записи — ни одного вызова; IP вне подсети пропущен; `connTracker.remoteIPs`/`closeLAN`
- [x] ➕ `State.LANSubnet netip.Prefix` и `DetectLAN` → `netip.Prefix` сделаны здесь (нужны для фильтра по подсети), а не в Task 4
- [x] ➕ `normalizeMAC` давал пустой октет для нуля (`2:a:b:c::1`) — такой MAC сломал бы `arp -S`; заменён на `route.CanonicalMAC` (двузначные октеты)
- [x] `make test` — должно пройти

### Task 4: LANSubnet в State и автообнаружение в Accept

**Files:**
- Modify: `internal/utils/route/route.go` (`DetectLAN` → `netip.Prefix`)
- Modify: `internal/service/service.go`
- Modify: `internal/service/cisco.go`
- Modify: `internal/service/proxy.go`

- [x] `State.LANSubnet netip.Prefix`, заполнять в `detectLAN` (сделано в Task 3)
- [ ] `acceptConns` — метод с флагом `lan`; хук только для LAN-соединений и только при `discoveryEnabled`
- [ ] хук: проверка подсети, `needsRefresh`, `LookupARP`, `registry.seen`; в горутине соединения до `ServeConn`
- [ ] Info «LAN client discovered» только для новых IP
- [ ] тесты: `needsRefresh` (неизвестный / пустой MAC / свежий / устаревший `LastSeen`); проверка подсети
- [ ] `make test` — должно пройти

### Task 5: Отслеживание смены сети и переоткрытие LAN-листенера

**Files:**
- Modify: `internal/utils/route/route.go` (fallback предпочитает текущий интерфейс — `pickCandidate` сделан в Task 3)
- Modify: `internal/service/cisco.go`
- Modify: `internal/service/proxy.go`
- Modify: `internal/service/service.go`

- [ ] `detectLAN` на каждом tick; чистая `lanChanged(cur, next)`; дебаунс на два тика через `pendingLAN`
- [ ] при изменении: `setStatus`, `registry.resetNetwork()`, неблокирующий сигнал в `lanCheck`
- [ ] в `startProxy` — владелец LAN-листенера: сравнение с открытым снимком, переоткрытие, `closeLAN`, повтор bind раз в 10 с
- [ ] намеренное закрытие LAN-листенера не фатально; неожиданное — по-прежнему фатально
- [ ] Info `LAN changed old=en0/192.168.0.0/24 new=en1/10.0.0.0/24`
- [ ] тесты `lanChanged`: тот же снимок / другой iface / другая подсеть / пустой → найденный / найденный → пустой (не изменение); дебаунс: одиночный выброс не применяется, два тика подряд — применяется; fallback предпочитает текущий интерфейс (чистый выбор из списка кандидатов)
- [ ] `make test` — должно пройти

### Task 6: Конфиг: необязательный MAC, auth, lan_discovery

**Files:**
- Modify: `cmd/config.go`, `cmd/main.go`
- Modify: `cmd/config_test.go`

- [x] `mac` валидируется только если непустой
- [x] `socks_user`/`socks_password` — только парой; `lan_discovery` — bool
- [x] передать новые поля в `service.New` (вариант: структура опций вместо растущего списка аргументов)
- [x] тесты: только `ip` — ок; невалидный `mac` — ошибка; невалидный `ip` — ошибка; только `socks_user` — ошибка; пара — ок
- [x] `make test` — должно пройти

### Task 7: SOCKS-аутентификация на LAN-листенере и гейт автообнаружения

**Files:**
- Modify: `internal/service/proxy.go`
- Modify: `internal/service/service.go`

- [ ] два `socks5.Server`: loopback без auth, LAN — с `WithCredential` при заданном auth
- [ ] `discoveryEnabled = auth || lan_discovery`; Warn при открытом LAN-прокси
- [ ] тесты: `discoveryEnabled` (таблица); in-process SOCKS5-рукопожатие через `net.Pipe` к LAN-серверу: без кредов — отказ, с верными — `05 00`
- [ ] `make test` — должно пройти

### Task 8: VPN-гейт CONNECT

**Files:**
- Modify: `internal/service/proxy.go`

- [ ] гейт-резолвер (`WithResolver`) и connect-middleware с явным `SendReply`; Debug-лог
- [ ] тесты: in-process CONNECT через `net.Pipe` при `CiscoConnected=false` на IP получает reply `0x03`, на FQDN — `0x04` без вызова резолвера; при `true` — проходит дальше
- [ ] `make test` — должно пройти

### Task 9: Verify acceptance criteria

- [ ] прокси доступен из LAN без `lan_clients` в конфиге (автообнаружение при заданном auth)
- [ ] без auth и без `lan_discovery` поведение как раньше (только `lan_clients`)
- [ ] ротация MAC клиента не ломает доступ и не вызывает ежесекундный перепин
- [ ] смена Wi‑Fi сети не требует рестарта
- [ ] без VPN CONNECT отклоняется, а не уходит мимо туннеля
- [ ] старый конфиг `{ip, mac}` работает как раньше
- [ ] `make test`, `make vet`, `golangci-lint run`

### Task 10: [Final] Update documentation

- [ ] обновить `CLAUDE.md`: LAN client pinning (реестр, adopt, автообнаружение, гейт auth/`lan_discovery`), снимок LAN больше не «один раз» (дебаунс, переоткрытие листенера), VPN-гейт CONNECT, список покрытого тестами чистого кода
- [ ] обновить README: необязательные `lan_clients`/`mac`, `socks_user`/`socks_password`, `lan_discovery`, пример конфига twarp-клиента с кредами
- [ ] переместить план в `docs/plans/completed/`

## Post-Completion

*Ручная проверка на живом VPN (нужен root, нельзя гонять из сессии Claude — full-tunnel VPN режет доступ)*

**Manual verification:**
- запуск с auth и без `lan_clients`: twarp-клиент подключается → в логе `LAN client discovered`, соединение работает; без кредов (`curl --socks5 <мак>:8080`) — отказ
- запуск без auth и без `lan_discovery` со старым конфигом `{ip, mac}` — как раньше
- на клиенте «забыть сеть» / переподключиться (новый частный MAC) → `LAN client MAC changed`, без ежесекундного `LAN client pinned`
- ротация MAC при **уже запиненной** записи (`arp -S … temp`): перезаписывает ли ядро её по ARP от клиента? Если запись остаётся статической, ответы уходят на старый MAC до истечения (~20 мин) — тогда нужен механизм сброса (например, удалить наш пин, когда клиент перестал отвечать)
- переключить мак на другую Wi‑Fi сеть при работающем сервере → `LAN changed`, LAN-листенер переоткрыт, клиент в новой сети работает без рестарта; статический клиент из старой сети не пинится в новой
- долгая SSH-сессия через прокси > TTL — не рвётся
- во время `Reconnecting` CONNECT с twarp-клиента получает быстрый отказ, а не таймаут; в tcpdump на `en0` нет трафика к корпоративным адресам
- после перевода пробы twarp на SOCKS-рукопожатие: в tcpdump `05 01 00`/`05 02 00 02` вместо голого `FIN`
- корпоративный DNS по TCP через туннель: `dig +tcp @<corp-dns> <имя>` с мака при поднятом VPN. Если не отвечает — DNS шлюза в twarp (`type: tcp`, detour `gateway`) не работает, нужна отдельная задача (LAN-доступ к нашему DNS-форвардеру)
- `.local`-имя мака резолвится с twarp-клиента при поднятом Cisco на маке (нужно twarpd-плану)

**Rollout:**
- сначала в twarp прописать креды шлюза (`twarp gateway auth`, twarp-план Task 10), затем включить `socks_user`/`socks_password` здесь — иначе twarp-клиент получит отказ аутентификации
