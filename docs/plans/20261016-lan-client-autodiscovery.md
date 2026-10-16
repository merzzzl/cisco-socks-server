# LAN Client Autodiscovery & Network Change Tracking

## Overview

Сейчас доступность прокси из LAN держится на статической паре `lan_clients: {ip, mac}` в `~/.cisco-socks5.yaml` и на снимке LAN-интерфейса, который снимается один раз до первого коннекта. При смене сети (другой Wi‑Fi, другой роутер) ломаются все три опоры:

| Что | Где задано | Почему ломается |
|---|---|---|
| IP клиента | `lan_clients[].ip` | DHCP новой сети выдаёт другой адрес |
| MAC клиента | `lan_clients[].mac` | клиент использует частный (рандомизированный, ротируемый) Wi‑Fi MAC |
| LAN-интерфейс/подсеть мака | снимок в `detectLAN` | никогда не обновляется после первого успеха — нужен рестарт |

Цель: прокси должен оставаться доступным из LAN после смены сети **без правки конфига и без рестарта**. `lan_clients` становится необязательным пред-заполнением.

## Context (from discovery)

### Диагностика (2026-10-15/16)

- После коннекта Cisco маршрутизирует всю подсеть LAN в туннель: `192.168.0  link#11  UCS  utun4` (раньше было `192.168.0.0/16 → utun4`). Host-пины `192.168.0.214 → en0` Cisco терпит (`UHLS en0`).
- В конфиге был `f4:d4:88:85:75:6f`, но ядро само выучило по ARP `12:49:61:d3:72:48` (бит locally-administered → частный адрес). Пиннер каждую секунду считал это дрейфом и перезаписывал рабочую запись устаревшим MAC → ответы уходили несуществующему устройству. Лог: `LAN client pinned` каждую секунду + периодические `arp -S ... cannot intuit interface index` (в моменты, когда Cisco успевал снести host-запись).
- Через ночь у того же клиента MAC снова сменился: `82:b4:3b:8e:d2:f3` — т.е. MAC ротируется, статический MAC в конфиге в принципе не жизнеспособен.
- После исправления MAC в конфиге: ARP стабилен, tcpdump показал полный handshake `SYN → SYN-ACK → ACK`, т.е. L2/L3-путь работает. Клиент сразу после ACK шлёт `FIN` без данных — это отдельная проблема на стороне клиента (проверка порта / настройка клиента), **вне скоупа этого плана**.
- Ключевой факт для дизайна: клиент перед первым SYN шлёт ARP-запрос на IP мака, поэтому к моменту `Accept` ядро мака уже знает **актуальный** MAC клиента (`arp -n <ip>` → `on en0`).

### Файлы

- `internal/service/service.go` — `LANClient`, `State`, `startPinner` (сейчас стартует только при непустом `lan_clients`)
- `internal/service/proxy.go` — `proxyListeners`, `acceptConns` (LAN-листенер с `IP_BOUND_IF`, `net.ErrClosed` = фатально)
- `internal/service/cisco.go` — `detectLAN` (снимок один раз), supervisor tick
- `internal/utils/route/route.go` — `DetectLAN`, `EnsureClientPinned`, `arpEntryMatches`, `normalizeMAC`
- `cmd/config.go` — валидация `lan_clients` (сейчас `mac` обязателен)
- `internal/utils/tui/status.go` — отображение bind-интерфейса

### Паттерны

- Мутация состояния только через `setStatus(func(*State))`; периодические циклы — через `sleepCtx`; все ожидания `ciscoReady` селектят `ctx.Done()`.
- Shell-out'ы через `shell.Run`; чистые парсеры покрыты тестами (`route_test.go`).
- Проверка пина read-only (`arp -n`), мутация (`arp -S`) — только при дрейфе: безусловный `arp -S` рвёт in-flight кадры.

## Development Approach

- **testing approach**: Regular (code first, then tests). Тестами покрывается только чистый код (парсеры, реестр клиентов, логика решения «adopt/repin») — остальное требует root и живого VPN, как и во всём репо.
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run `make test` and `make vet` after each change
- maintain backward compatibility: существующий конфиг с `lan_clients: {ip, mac}` продолжает работать

## Testing Strategy

- **unit tests**: парсер ARP-вывода, реестр клиентов (add/expire/reset/snapshot), решение пиннера (match / adopt / repin), сравнение снимков LAN, валидация конфига с необязательным `mac`.
- **e2e tests**: в проекте нет; ручная проверка — в Post-Completion.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope

## Solution Overview

Выбрана комбинация трёх механизмов:

1. **Автообнаружение клиентов (основной).** На каждый `Accept` на LAN-листенере берём IP пира, проверяем что он в LAN-подсети, читаем его MAC из `arp -n` (ядро уже выучило его из ARP-запроса клиента) и регистрируем в реестре пиннера. Конфиг не нужен вообще.
2. **MAC из ARP, а не из конфига (fallback для `lan_clients`).** Если в ARP есть запись для клиента **на правильном интерфейсе**, но с другим MAC — пиннер не перебивает её, а принимает новый MAC (Warn в лог «client MAC changed»). Перепин (`route change` + `arp -S`) — только если записи нет или она ушла на чужой интерфейс (`utun*`). Это лечит ротацию частного MAC и для статических, и для обнаруженных клиентов. `mac` в конфиге становится необязательным.
3. **Отслеживание смены сети.** Периодически (каждый tick supervisor'а) перепроверяем LAN-интерфейс и подсеть. При изменении: обновляем `State`, сбрасываем обнаруженных клиентов, переоткрываем LAN-листенер на новом интерфейсе (без рестарта процесса).

Отвергнуто:
- Только вариант 2 — IP всё равно пришлось бы вписывать руками.
- Резервация DHCP / отключение частного MAC на клиенте — работает, но надо делать в каждой новой сети заново.
- mDNS/hostname клиента — DNS под Cisco идёт через туннель, лишняя сложность.

Компромисс: принятие MAC из ARP доверяет LAN (ARP-спуфинг из локалки может перенаправить ответы прокси). Для домашней сети приемлемо; прокси и так без аутентификации.

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
```

`arpEntryMatches` переписывается поверх `parseArpEntry`.

### Решение пиннера (чистая функция)

```go
type pinAction int // pinOK | pinAdopt | pinRepin

func decidePin(entry ArpEntry, found bool, wantMAC, iface string) pinAction
```

- `found && entry.Iface == iface && MAC совпадает` → `pinOK` (ничего не делаем)
- `found && entry.Iface == iface && MAC другой` → `pinAdopt` (обновить MAC в реестре, Warn, без мутаций ARP)
- `wantMAC == ""` и записи нет → ничего (ждём, пока клиент сам появится в ARP)
- иначе → `pinRepin` (`route change` + `arp -S <ip> <mac> temp`)

`EnsureClientPinned` разделяется на `LookupARP` + `Pin(ctx, ip, mac, iface)`; оркестрация — в `startPinner`.

### Реестр клиентов (`service`)

```go
type clientEntry struct {
    MAC      string
    Static   bool      // из lan_clients — не истекает, не сбрасывается при смене сети
    LastSeen time.Time // обновляется на каждый Accept
}

type clientRegistry struct {
    mu      sync.Mutex
    clients map[string]*clientEntry // key: IP
}

func (r *clientRegistry) seen(ip, mac string, now time.Time)
func (r *clientRegistry) setMAC(ip, mac string)
func (r *clientRegistry) snapshot() map[string]string // ip → mac
func (r *clientRegistry) expire(now time.Time, ttl time.Duration) []string
func (r *clientRegistry) resetDiscovered()
```

- TTL обнаруженных клиентов: `discoveredClientTTL = 30 * time.Minute` от `LastSeen`. Активные соединения обновляют `LastSeen` только при Accept — для долгих SSH-сессий TTL считается от последнего Accept, но пин истекает лишь из реестра; ARP-запись `temp` живёт ~20 мин, так что при истечении клиент просто будет обнаружен заново на следующем соединении. ⚠️ Проверить на практике, не рвётся ли долгая сессия — при необходимости продлевать `LastSeen`, пока у IP есть живые соединения в `connTracker`.
- `startPinner` запускается всегда (не только при непустом `lan_clients`), итерирует `snapshot()`.
- Статические записи из конфига с пустым `mac` — `wantMAC = ""`, MAC подхватывается из ARP через `pinAdopt`.

### Хук в Accept (`proxy.go`)

`acceptConns` получает опциональный `onAccept func(net.Conn)` — передаётся только для LAN-листенера:

1. `remote := conn.RemoteAddr().(*net.TCPAddr).IP`
2. проверить `State.LANSubnet.Contains(remote)` (нужно новое поле `LANSubnet` в `State`; сейчас подсеть только логируется)
3. `route.LookupARP(ctx, ip)` — если запись на `State.LANInterface` → `registry.seen(ip, mac, now)`; Info «LAN client discovered» только для новых IP
4. если записи нет — зарегистрировать с пустым MAC, пиннер подхватит через `pinAdopt` на следующем тике

Вызов `arp -n` синхронно в Accept-петле недопустим (shell-out на каждое соединение тормозит приём) → хук выполняется в горутине обслуживания соединения, до `ServeConn`, и только для IP, которых ещё нет в реестре или у которых `LastSeen` старше 1 мин.

### Смена сети

- `detectLAN` перестаёт быть «один раз»: на каждом tick supervisor'а вычисляется снимок `{iface, subnet}` через `route.DetectLAN`. После коннекта default через `en0` остаётся в таблице (`default 192.168.0.1 UGScIg en0`), поэтому детект работает и при поднятом VPN. ⚠️ Если Cisco когда-нибудь уберёт non-tunnel default — fallback `scanRFC1918` всё равно найдёт интерфейс.
- Чистая функция `lanChanged(old, new lanSnapshot) bool`.
- При изменении:
  - `setStatus`: новые `LANInterface`/`LANSubnet`
  - `registry.resetDiscovered()` (статические остаются)
  - сигнал прокси через `lanChanged chan struct{}` (буфер 1, неблокирующая отправка)
- В `startProxy`: LAN-листенер управляется отдельной горутиной-владельцем — по сигналу закрывает старый листенер и открывает новый `listenBoundToInterface`. Чтобы намеренное закрытие не считалось фатальным, `acceptConns` для LAN-листенера возвращается без ошибки, если закрытие было инициировано владельцем (флаг/`context` на листенер). Loopback-листенер не трогается.
- Соединения, принятые на старом интерфейсе, закрываются (`connTracker`) — их путь всё равно мёртв.
- Cisco сам переподключается при смене сети; `PFDisabled` уже сбрасывается на `Reconnecting/Disconnected` — менять не нужно.

### Конфиг

- `lan_clients[].mac` — необязательный (валидируется только если задан).
- `lan_clients` целиком — необязательный (и так был).

## What Goes Where

- **Implementation Steps** — код, тесты, документация в этом репо.
- **Post-Completion** — ручная проверка на живом VPN со сменой сети.

## Implementation Steps

### Task 1: ARP-парсер и разделение EnsureClientPinned

**Files:**
- Modify: `internal/utils/route/route.go`
- Modify: `internal/utils/route/route_test.go`

- [ ] добавить `ArpEntry`, `parseArpEntry`, `LookupARP` (через `shell.Run`)
- [ ] переписать `arpEntryMatches` поверх `parseArpEntry` (или удалить, если не нужен)
- [ ] выделить `Pin(ctx, ip, mac, iface) error` (`route change` + `arp -S ... temp`) из `EnsureClientPinned`
- [ ] добавить чистую `decidePin(entry, found, wantMAC, iface) pinAction`
- [ ] тесты `parseArpEntry`: обычная запись, `permanent`, `-- no entry`, `(incomplete)`, MAC без ведущих нулей, запись на `utun4`
- [ ] тесты `decidePin`: OK / adopt (другой MAC на том же iface) / repin (нет записи, чужой iface) / пустой wantMAC без записи
- [ ] `make test` — должно пройти

### Task 2: Реестр клиентов

**Files:**
- Create: `internal/service/clients.go`
- Create: `internal/service/clients_test.go`

- [ ] реализовать `clientRegistry` (`seen`, `setMAC`, `snapshot`, `expire`, `resetDiscovered`)
- [ ] конструктор из `[]LANClient` (статические записи)
- [ ] тесты: статические не истекают и не сбрасываются; обнаруженные истекают по TTL; `seen` обновляет MAC и `LastSeen`; `snapshot` — копия
- [ ] `make test` — должно пройти

### Task 3: Пиннер поверх реестра + adopt MAC

**Files:**
- Modify: `internal/service/service.go`

- [ ] `Service` держит `*clientRegistry` вместо `[]LANClient`
- [ ] `startPinner` запускается всегда; итерирует `snapshot()`, использует `LookupARP` + `decidePin`
- [ ] `pinAdopt` → `registry.setMAC` + `slog.Warn("LAN client MAC changed", ...)`, без мутации ARP
- [ ] `pinRepin` → `route.Pin`; Info при успехе, Debug при ошибке (как сейчас)
- [ ] раз в N тиков — `registry.expire`, Info «LAN client expired»
- [ ] тесты: логика тика вынесена в чистую функцию над `decidePin` — покрыть table-driven
- [ ] `make test` — должно пройти

### Task 4: LANSubnet в State и автообнаружение в Accept

**Files:**
- Modify: `internal/service/service.go`
- Modify: `internal/service/cisco.go`
- Modify: `internal/service/proxy.go`

- [ ] добавить `State.LANSubnet *net.IPNet`, заполнять в `detectLAN`
- [ ] `acceptConns` принимает `onAccept func(net.Conn)` (nil для loopback)
- [ ] хук для LAN: проверка подсети, троттлинг по `LastSeen`, `LookupARP`, `registry.seen`; выполняется в горутине соединения до `ServeConn`
- [ ] Info «LAN client discovered» только для новых IP
- [ ] тесты: чистый хелпер «нужно ли обновлять клиента» (в подсети / вне / свежий LastSeen)
- [ ] `make test` — должно пройти

### Task 5: Отслеживание смены сети и переоткрытие LAN-листенера

**Files:**
- Modify: `internal/service/cisco.go`
- Modify: `internal/service/proxy.go`
- Modify: `internal/service/service.go`

- [ ] `detectLAN` выполняется на каждом tick; чистая `lanChanged(old, new)`
- [ ] при изменении: `setStatus`, `registry.resetDiscovered()`, неблокирующий сигнал в `lanChanged`
- [ ] в `startProxy` — владелец LAN-листенера: по сигналу закрыть старый, открыть новый, закрыть соединения со старого интерфейса
- [ ] намеренное закрытие LAN-листенера не фатально; неожиданное — по-прежнему фатально
- [ ] Info «LAN changed: en0 192.168.0.0/24 → en1 10.0.0.0/24»
- [ ] тесты `lanChanged`: тот же снимок / другой iface / другая подсеть / пустой → найденный
- [ ] `make test` — должно пройти

### Task 6: Необязательный MAC в конфиге

**Files:**
- Modify: `cmd/config.go`
- Modify/Create: `cmd/config_test.go`

- [ ] `mac` валидируется только если непустой
- [ ] тесты: только `ip` — ок; невалидный `mac` — ошибка; невалидный `ip` — ошибка
- [ ] `make test` — должно пройти

### Task 7: Verify acceptance criteria

- [ ] прокси доступен из LAN без `lan_clients` в конфиге (автообнаружение)
- [ ] ротация MAC клиента не ломает доступ и не вызывает ежесекундный перепин
- [ ] смена Wi‑Fi сети не требует рестарта
- [ ] старый конфиг `{ip, mac}` работает как раньше
- [ ] `make test`, `make vet`, `golangci-lint run`

### Task 8: [Final] Update documentation

- [ ] обновить `CLAUDE.md`: LAN client pinning (реестр, adopt, автообнаружение), снимок LAN больше не «один раз»
- [ ] обновить README (необязательный `lan_clients`, `mac`)
- [ ] переместить план в `docs/plans/completed/`

## Post-Completion

*Ручная проверка на живом VPN (нужен root, нельзя гонять из сессии Claude — full-tunnel VPN режет доступ)*

**Manual verification:**
- запуск без `lan_clients`: клиент подключается → в логе `LAN client discovered`, соединение работает
- на клиенте «забыть сеть» / переподключиться (новый частный MAC) → `LAN client MAC changed`, без ежесекундного `LAN client pinned`
- переключить мак на другую Wi‑Fi сеть при работающем сервере → `LAN changed`, LAN-листенер переоткрыт, клиент в новой сети работает без рестарта
- долгая SSH-сессия через прокси > TTL — не рвётся (см. ⚠️ в реестре)
- отдельно: разобраться, почему клиент шлёт `FIN` сразу после handshake без SOCKS-приветствия (настройка клиента, вне скоупа)
