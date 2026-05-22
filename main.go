package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ipwhoBaseURL    = "https://ipwho.is"
	ipinfoBaseURL   = "https://ipinfo.io"
	censysHostURL   = "https://search.censys.io/hosts"
	telegramTimeout = 50 * time.Second
)

var (
	apiHTTPClient = newHTTPClient(20 * time.Second)
	dnsCache      = newTTLCache[string]()
	geoCache      = newTTLCache[GeoBundle]()
	httpURLRe     = regexp.MustCompile(`(?i)https?://[^\s]+`)
	proxyRe       = regexp.MustCompile(`(?i)(vless|vmess|trojan|ss)://[^\s]+`)
	ipv4Re        = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	domainRe      = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)

	subscriptionUAChain = []string{
		"Happ/1.0",
		"v2RayTun/5.0",
		"ClashForAndroid/2.5.12",
		"ClashMeta/1.18.0",
		"ipwho-tg-bot-go/1.0",
	}
)

type Config struct {
	BotToken           string
	IPWhoAccessKey     string
	IPInfoToken        string
	CensysAPIID        string
	CensysAPISecret    string
	HWID               string
	QueueSize          int
	GeoConcurrency     int
	SubMessageDelay    time.Duration
	DNSCacheTTL        time.Duration
	GeoCacheTTL        time.Duration
	TelegramAPITimeout time.Duration
}

type TelegramClient struct {
	base  string
	http  *http.Client
}

type Update struct {
	UpdateID int64    `json:"update_id"`
	Message  *Message `json:"message"`
}

type Message struct {
	MessageID int64  `json:"message_id"`
	From      *User  `json:"from"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
}

type Chat struct {
	ID int64 `json:"id"`
}

type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

type InlineKeyboardButton struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

type Job struct {
	Message Message
	User    User
	Text    string
}

type IPWhoResponse struct {
	Success     bool    `json:"success"`
	Message     string  `json:"message"`
	IP          string  `json:"ip"`
	Type        string  `json:"type"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Flag        struct {
		Emoji string `json:"emoji"`
	} `json:"flag"`
	Connection struct {
		ASN    any    `json:"asn"`
		Org    string `json:"org"`
		ISP    string `json:"isp"`
		Domain string `json:"domain"`
	} `json:"connection"`
	Timezone struct {
		ID string `json:"id"`
	} `json:"timezone"`
}

type IPInfoResponse struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
	Anycast  bool   `json:"anycast"`
	Bogon    bool   `json:"bogon"`
	Error    *struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	} `json:"error"`
}

type CensysHostResponse struct {
	Result struct {
		Services []struct {
			Port        int    `json:"port"`
			ServiceName string `json:"service_name"`
			Transport   string `json:"transport_protocol"`
		} `json:"services"`
		Location struct {
			Country     string `json:"country"`
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
		} `json:"location"`
	} `json:"result"`
	Error string `json:"error"`
}

type GeoBundle struct {
	IP       string
	MaxMind  *IPWhoResponse
	IPInfo   *IPInfoResponse
	Censys   *CensysHostResponse
	Warnings []string
}

type Proxy struct {
	Proto       string
	UUID        string
	Host        string
	Port        string
	Name        string
	Security    string
	SNI         string
	Network     string
	Path        string
	Fingerprint string
	Flow        string
	PublicKey   string
	ShortID     string
}

type cacheEntry[T any] struct {
	value     T
	expiresAt time.Time
}

type ttlCache[T any] struct {
	mu    sync.RWMutex
	items map[string]cacheEntry[T]
}

type SubscriptionResult struct {
	Proxy  Proxy
	IP     string
	Bundle GeoBundle
}

func main() {
	loadDotEnv(".env")
	cfg := loadConfig()
	if cfg.BotToken == "" {
		log.Fatal("BOT_TOKEN is not set")
	}

	bot := NewTelegramClient(cfg.BotToken, cfg.TelegramAPITimeout)
	jobs := make(chan Job, cfg.QueueSize)

	log.Printf("starting ipwho-tg-bot-go; hwid=%s queue=%d geo_concurrency=%d dns_cache=%s geo_cache=%s",
		cfg.HWID, cfg.QueueSize, cfg.GeoConcurrency, cfg.DNSCacheTTL, cfg.GeoCacheTTL)
	if cfg.IPWhoAccessKey == "" {
		log.Println("IPWHO_ACCESS_KEY is not set, ipwho.is free limits apply")
	}
	if cfg.CensysAPIID == "" || cfg.CensysAPISecret == "" {
		log.Println("Censys API credentials are not set, using Censys links only")
	}

	go worker(context.Background(), cfg, bot, jobs)
	poll(context.Background(), cfg, bot, jobs)
}

func loadConfig() Config {
	queueSize := envInt("QUEUE_SIZE", 128)
	geoConcurrency := envInt("GEO_CONCURRENCY", 8)
	delayMs := envInt("SUB_MESSAGE_DELAY_MS", 450)
	dnsTTLMinutes := envInt("DNS_CACHE_TTL_MINUTES", 30)
	geoTTLMinutes := envInt("GEO_CACHE_TTL_MINUTES", 10)
	return Config{
		BotToken:           os.Getenv("BOT_TOKEN"),
		IPWhoAccessKey:     os.Getenv("IPWHO_ACCESS_KEY"),
		IPInfoToken:        os.Getenv("IPINFO_TOKEN"),
		CensysAPIID:        os.Getenv("CENSYS_API_ID"),
		CensysAPISecret:    os.Getenv("CENSYS_API_SECRET"),
		HWID:               getHWID(),
		QueueSize:          queueSize,
		GeoConcurrency:     geoConcurrency,
		SubMessageDelay:    time.Duration(delayMs) * time.Millisecond,
		DNSCacheTTL:        time.Duration(dnsTTLMinutes) * time.Minute,
		GeoCacheTTL:        time.Duration(geoTTLMinutes) * time.Minute,
		TelegramAPITimeout: telegramTimeout,
	}
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 60 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          512,
			MaxIdleConnsPerHost:   64,
			MaxConnsPerHost:       128,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func newTTLCache[T any]() *ttlCache[T] {
	return &ttlCache[T]{items: make(map[string]cacheEntry[T])}
}

func (c *ttlCache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	var zero T
	if !ok {
		return zero, false
	}
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return zero, false
	}
	return entry.value, true
}

func (c *ttlCache[T]) Set(key string, value T, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.items[key] = cacheEntry[T]{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if key == "" || os.Getenv(key) != "" {
			continue
		}
		_ = os.Setenv(key, val)
	}
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	val, err := strconv.Atoi(raw)
	if err != nil || val <= 0 {
		return fallback
	}
	return val
}

func getHWID() string {
	if val := os.Getenv("HWID"); val != "" {
		return val
	}
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if len(iface.HardwareAddr) > 0 {
				return strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
			}
		}
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func NewTelegramClient(token string, timeout time.Duration) *TelegramClient {
	return &TelegramClient{
		base:  "https://api.telegram.org/bot" + token,
		http:  newHTTPClient(timeout),
	}
}

func (t *TelegramClient) call(ctx context.Context, method string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram %s: HTTP %d: %s", method, resp.StatusCode, string(data))
	}

	var envelope struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if !envelope.OK {
		if envelope.Description == "" {
			envelope.Description = "unknown Telegram API error"
		}
		return errors.New(envelope.Description)
	}
	if out != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

func (t *TelegramClient) getUpdates(ctx context.Context, offset int64) ([]Update, error) {
	payload := map[string]any{
		"offset":          offset,
		"timeout":         30,
		"allowed_updates": []string{"message"},
	}
	var updates []Update
	err := t.call(ctx, "getUpdates", payload, &updates)
	return updates, err
}

func (t *TelegramClient) sendMessage(ctx context.Context, chatID int64, text string, replyTo int64, markup *InlineKeyboardMarkup) (*Message, error) {
	payload := map[string]any{
		"chat_id":                  chatID,
		"text":                     clampRunes(text, 3900),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if replyTo > 0 {
		payload["reply_to_message_id"] = replyTo
		payload["allow_sending_without_reply"] = true
	}
	if markup != nil {
		payload["reply_markup"] = markup
	}
	var msg Message
	if err := t.call(ctx, "sendMessage", payload, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (t *TelegramClient) editMessage(ctx context.Context, chatID, messageID int64, text string, markup *InlineKeyboardMarkup) error {
	payload := map[string]any{
		"chat_id":                  chatID,
		"message_id":               messageID,
		"text":                     clampRunes(text, 3900),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if markup != nil {
		payload["reply_markup"] = markup
	}
	return t.call(ctx, "editMessageText", payload, nil)
}

func poll(ctx context.Context, cfg Config, bot *TelegramClient, jobs chan<- Job) {
	var offset int64
	for {
		updates, err := bot.getUpdates(ctx, offset)
		if err != nil {
			log.Printf("getUpdates failed: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, update := range updates {
			offset = update.UpdateID + 1
			if update.Message == nil || strings.TrimSpace(update.Message.Text) == "" {
				continue
			}
			handleUpdate(ctx, cfg, bot, jobs, *update.Message)
		}
	}
}

func handleUpdate(ctx context.Context, cfg Config, bot *TelegramClient, jobs chan<- Job, msg Message) {
	text := strings.TrimSpace(msg.Text)
	user := User{}
	if msg.From != nil {
		user = *msg.From
	}

	if strings.HasPrefix(text, "/start") || strings.HasPrefix(text, "/help") {
		_, err := bot.sendMessage(ctx, msg.Chat.ID, startText(), msg.MessageID, nil)
		if err != nil {
			log.Printf("send start failed: %v", err)
		}
		return
	}

	items := splitBatchItems(text)
	if len(items) == 0 {
		return
	}
	queued := 0
	for _, item := range items {
		job := Job{Message: msg, User: user, Text: item}
		select {
		case jobs <- job:
			queued++
		default:
			_, _ = bot.sendMessage(ctx, msg.Chat.ID, "⚠️ Очередь переполнена. Попробуйте еще раз чуть позже.", msg.MessageID, nil)
			return
		}
	}
	if queued > 1 {
		_, _ = bot.sendMessage(ctx, msg.Chat.ID, fmt.Sprintf("⏳ Принял строк: <b>%d</b>. Обработаю по очереди.", queued), msg.MessageID, nil)
	} else if len(jobs) > 1 {
		_, _ = bot.sendMessage(ctx, msg.Chat.ID, fmt.Sprintf("⏳ Принял. Перед вами в очереди: <b>%d</b>.", len(jobs)-1), msg.MessageID, nil)
	}
}

func worker(ctx context.Context, cfg Config, bot *TelegramClient, jobs <-chan Job) {
	for job := range jobs {
		name := job.User.Username
		if name == "" {
			name = job.User.FirstName
		}
		log.Printf("processing message from user=%d username=%q", job.User.ID, name)
		if err := processJob(ctx, cfg, bot, job); err != nil {
			log.Printf("job failed: %v", err)
			_, _ = bot.sendMessage(ctx, job.Message.Chat.ID, "⚠️ Ошибка: "+escape(err.Error()), job.Message.MessageID, nil)
		}
	}
}

func splitBatchItems(text string) []string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	items := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			items = append(items, line)
		}
	}
	return items
}

func processJob(ctx context.Context, cfg Config, bot *TelegramClient, job Job) error {
	text := strings.TrimSpace(job.Text)
	if match := proxyRe.FindString(text); match != "" {
		return proxyAndReply(ctx, cfg, bot, job, match)
	}
	if match := httpURLRe.FindString(text); match != "" {
		return subscriptionAndReply(ctx, cfg, bot, job, match)
	}
	if target, kind := extractTarget(text); target != "" {
		if kind == "domain" {
			return domainAndReply(ctx, cfg, bot, job, strings.ToLower(target))
		}
		return ipAndReply(ctx, cfg, bot, job, target)
	}
	_, err := bot.sendMessage(ctx, job.Message.Chat.ID, unknownText(), job.Message.MessageID, nil)
	return err
}

func startText() string {
	return strings.Join([]string{
		"🛰 <b>IPWho Bot</b>",
		"",
		"Отправьте IP, домен, proxy-ключ или ссылку на подписку.",
		"Можно отправить сразу несколько строк через Enter.",
		"",
		"Поддерживается:",
		"8.8.8.8",
		"example.com",
		"45.150.65.65:443",
		"vless://... / vmess://... / trojan://... / ss://...",
		"https://... подписка",
		"",
		"⏳ Ответы идут через очередь, поэтому несколько пользователей не мешают друг другу.",
	}, "\n")
}

func unknownText() string {
	return strings.Join([]string{
		"⚠️ Не могу определить тип.",
		"",
		"Пришлите IP, домен, proxy-ключ или ссылку на подписку.",
	}, "\n")
}

func ipAndReply(ctx context.Context, cfg Config, bot *TelegramClient, job Job, ip string) error {
	status, err := bot.sendMessage(ctx, job.Message.Chat.ID, "🔎 Ищу <code>"+escape(ip)+"</code>...", job.Message.MessageID, nil)
	if err != nil {
		return err
	}
	bundle := geoForIP(ctx, cfg, ip)
	text := formatGeo(job.Text, bundle)
	markup := makeKeyboard(ip, asnFromBundle(bundle))
	if err := bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, text, markup); err != nil {
		return err
	}
	return nil
}

func domainAndReply(ctx context.Context, cfg Config, bot *TelegramClient, job Job, domain string) error {
	status, err := bot.sendMessage(ctx, job.Message.Chat.ID, "🧭 Резолвлю <code>"+escape(domain)+"</code>...", job.Message.MessageID, nil)
	if err != nil {
		return err
	}
	ip, err := resolveDomain(ctx, domain, cfg.DNSCacheTTL)
	if err != nil {
		return bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, "⚠️ Не удалось резолвнуть домен: <code>"+escape(domain)+"</code>", nil)
	}
	bundle := geoForIP(ctx, cfg, ip)
	text := formatGeo(domain, bundle)
	markup := makeKeyboard(ip, asnFromBundle(bundle))
	if err := bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, text, markup); err != nil {
		return err
	}
	return nil
}

func proxyAndReply(ctx context.Context, cfg Config, bot *TelegramClient, job Job, uri string) error {
	status, err := bot.sendMessage(ctx, job.Message.Chat.ID, "🧩 Анализирую ключ...", job.Message.MessageID, nil)
	if err != nil {
		return err
	}
	proxy, err := parseProxyURI(uri)
	if err != nil {
		return bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, "⚠️ Не удалось разобрать ключ: "+escape(err.Error()), nil)
	}
	ip, err := resolveHostMaybe(ctx, proxy.Host, cfg.DNSCacheTTL)
	if err != nil {
		ip = proxy.Host
	}
	bundle := geoForIP(ctx, cfg, ip)
	text := formatProxy(proxy, bundle, "")
	markup := makeKeyboard(ip, asnFromBundle(bundle))
	if err := bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, text, markup); err != nil {
		return err
	}
	return nil
}

func subscriptionAndReply(ctx context.Context, cfg Config, bot *TelegramClient, job Job, subURL string) error {
	status, err := bot.sendMessage(ctx, job.Message.Chat.ID, "📥 Загружаю подписку...", job.Message.MessageID, nil)
	if err != nil {
		return err
	}
	lines, headers, err := fetchSubscriptionLines(ctx, cfg, subURL)
	if err != nil {
		return bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, "⚠️ Ошибка загрузки подписки: "+escape(err.Error()), nil)
	}

	var proxies []Proxy
	var errorEntries []Proxy
	for _, line := range lines {
		proxy, err := parseProxyURI(line)
		if err != nil {
			continue
		}
		if isErrorEntry(proxy) {
			errorEntries = append(errorEntries, proxy)
			continue
		}
		proxies = append(proxies, proxy)
	}

	if len(errorEntries) > 0 && len(proxies) == 0 {
		reason := subscriptionRejectReason(headers)
		names := make([]string, 0, min(len(errorEntries), 3))
		for i := 0; i < min(len(errorEntries), 3); i++ {
			names = append(names, errorEntries[i].Name)
		}
		return bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, strings.Join([]string{
			"⚠️ Сервер отклонил запрос.",
			"",
			"Причина: " + escape(reason),
			"Ответ: " + escape(strings.Join(names, ", ")),
			"",
			"HWID этого бота:",
			"<code>" + escape(cfg.HWID) + "</code>",
		}, "\n"), nil)
	}

	if len(proxies) == 0 {
		return bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, "⚠️ В подписке не найдено поддерживаемых ключей.", nil)
	}

	total := len(proxies)
	if err := bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, fmt.Sprintf("📦 Подписка: <b>%d</b> серверов\n🌍 Получаю геолокацию...", total), nil); err != nil {
		log.Printf("status edit failed: %v", err)
	}

	results := prepareSubscriptionResults(ctx, cfg, proxies)
	for i, result := range results {
		text := formatProxy(result.Proxy, result.Bundle, fmt.Sprintf("%d/%d", i+1, total))
		_, sendErr := bot.sendMessage(ctx, job.Message.Chat.ID, text, job.Message.MessageID, makeKeyboard(result.IP, asnFromBundle(result.Bundle)))
		if sendErr != nil {
			log.Printf("subscription server %d/%d send failed: %v", i+1, total, sendErr)
			_, _ = bot.sendMessage(ctx, job.Message.Chat.ID, fmt.Sprintf("%d/%d\n<code>%s:%s</code>\nОшибка: %s", i+1, total, escape(result.Proxy.Host), escape(result.Proxy.Port), escape(sendErr.Error())), job.Message.MessageID, nil)
		}
		if i+1 < total {
			time.Sleep(cfg.SubMessageDelay)
		}
	}

	return bot.editMessage(ctx, job.Message.Chat.ID, status.MessageID, fmt.Sprintf("✅ Подписка: <b>%d</b> серверов\nГотово.", total), nil)
}

func prepareSubscriptionResults(ctx context.Context, cfg Config, proxies []Proxy) []SubscriptionResult {
	results := make([]SubscriptionResult, len(proxies))
	limit := cfg.GeoConcurrency
	if limit <= 0 {
		limit = 1
	}
	if limit > len(proxies) {
		limit = len(proxies)
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i := range proxies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			proxy := proxies[i]
			ip, err := resolveHostMaybe(ctx, proxy.Host, cfg.DNSCacheTTL)
			if err != nil {
				ip = proxy.Host
			}
			results[i] = SubscriptionResult{
				Proxy: proxy,
				IP:    ip,
			}
		}(i)
	}
	wg.Wait()

	uniqueIPs := make([]string, 0, len(results))
	seen := make(map[string]bool, len(results))
	for _, result := range results {
		if result.IP == "" || seen[result.IP] {
			continue
		}
		seen[result.IP] = true
		uniqueIPs = append(uniqueIPs, result.IP)
	}

	bundles := make(map[string]GeoBundle, len(uniqueIPs))
	var bundleMu sync.Mutex
	sem = make(chan struct{}, limit)
	for _, ip := range uniqueIPs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			bundle := geoForIP(ctx, cfg, ip)
			bundleMu.Lock()
			bundles[ip] = bundle
			bundleMu.Unlock()
		}(ip)
	}
	wg.Wait()
	for i := range results {
		results[i].Bundle = bundles[results[i].IP]
	}
	return results
}

func fetchIPWho(ctx context.Context, cfg Config, ip string) (*IPWhoResponse, error) {
	u, _ := url.Parse(ipwhoBaseURL + "/" + url.PathEscape(ip))
	if cfg.IPWhoAccessKey != "" {
		q := u.Query()
		q.Set("access_key", cfg.IPWhoAccessKey)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed IPWhoResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	if parsed.IP == "" {
		parsed.IP = ip
	}
	return &parsed, nil
}

func fetchIPInfo(ctx context.Context, cfg Config, ip string) (*IPInfoResponse, error) {
	u, _ := url.Parse(ipinfoBaseURL + "/" + url.PathEscape(ip) + "/json")
	if cfg.IPInfoToken != "" {
		q := u.Query()
		q.Set("token", cfg.IPInfoToken)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed IPInfoResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	if parsed.Error != nil {
		return &parsed, errors.New(parsed.Error.Message)
	}
	return &parsed, nil
}

func fetchCensys(ctx context.Context, cfg Config, ip string) (*CensysHostResponse, error) {
	if cfg.CensysAPIID == "" || cfg.CensysAPISecret == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://search.censys.io/api/v2/hosts/"+url.PathEscape(ip), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(cfg.CensysAPIID, cfg.CensysAPISecret)
	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return &CensysHostResponse{}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Censys HTTP %d", resp.StatusCode)
	}
	var parsed CensysHostResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	return &parsed, nil
}

func geoForIP(ctx context.Context, cfg Config, ip string) GeoBundle {
	if cached, ok := geoCache.Get(ip); ok {
		return cached
	}

	bundle := GeoBundle{IP: ip}
	if net.ParseIP(ip) == nil {
		bundle.Warnings = append(bundle.Warnings, "invalid IP")
		geoCache.Set(ip, bundle, cfg.GeoCacheTTL)
		return bundle
	}
	if isReservedIP(ip) {
		bundle.Warnings = append(bundle.Warnings, "Reserved range")
		geoCache.Set(ip, bundle, cfg.GeoCacheTTL)
		return bundle
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		maxMind, err := fetchIPWho(ctx, cfg, ip)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			bundle.MaxMind = maxMind
			if !maxMind.Success && maxMind.Message != "" {
				bundle.Warnings = append(bundle.Warnings, maxMind.Message)
			}
			return
		}
		bundle.Warnings = append(bundle.Warnings, "ipwho.is: "+err.Error())
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ipinfo, err := fetchIPInfo(ctx, cfg, ip)
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			bundle.IPInfo = ipinfo
			return
		}
		bundle.Warnings = append(bundle.Warnings, "ipinfo.io: "+err.Error())
	}()

	if cfg.CensysAPIID != "" && cfg.CensysAPISecret != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			censys, err := fetchCensys(ctx, cfg, ip)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				bundle.Censys = censys
				return
			}
			bundle.Warnings = append(bundle.Warnings, "Censys: "+err.Error())
		}()
	}

	wg.Wait()
	geoCache.Set(ip, bundle, cfg.GeoCacheTTL)
	return bundle
}

func formatGeo(subject string, bundle GeoBundle) string {
	flag := bundleFlag(bundle)
	lines := []string{
		firstNonEmpty(flag, "🌐") + " <code>" + escape(cleanSubject(subject)) + "</code>",
		"",
		"<code>" + escape(bundle.IP) + "</code>",
		"",
	}
	lines = append(lines, formatMaxMind(bundle.MaxMind)...)
	lines = append(lines, "")
	lines = append(lines, formatIPInfo(bundle.IPInfo, bundle.MaxMind)...)
	lines = append(lines, "")
	lines = append(lines, formatCensys(bundle.IP, bundle.Censys)...)
	if warning := userFacingWarning(bundle.Warnings); warning != "" {
		lines = append(lines, "", "⚠️ Note", escape(warning))
	}
	return strings.Join(lines, "\n")
}

func formatProxy(proxy Proxy, bundle GeoBundle, index string) string {
	title := proxy.Name
	if title == "" || title == "N/A" {
		title = strings.ToUpper(proxy.Proto)
	}
	flag := bundleFlag(bundle)
	lines := []string{}
	if index != "" {
		lines = append(lines, "📦 <b>"+escape(index)+"</b>", "")
	}
	lines = append(lines,
		firstNonEmpty(flag, "🧩")+" <code>"+escape(title)+"</code>",
		"<code>"+escape(proxy.Host+":"+proxy.Port)+"</code>",
		"",
		"<code>"+escape(bundle.IP)+"</code>",
		"",
	)
	lines = append(lines, formatMaxMind(bundle.MaxMind)...)
	lines = append(lines, "")
	lines = append(lines, formatIPInfo(bundle.IPInfo, bundle.MaxMind)...)
	lines = append(lines, "")
	lines = append(lines, formatCensys(bundle.IP, bundle.Censys)...)
	if warning := userFacingWarning(bundle.Warnings); warning != "" {
		lines = append(lines, "", "⚠️ Note", escape(warning))
	}
	return strings.Join(lines, "\n")
}

func formatMaxMind(data *IPWhoResponse) []string {
	if data == nil {
		return []string{"🌍 MaxMind", "N/A", "N/A"}
	}
	if !data.Success {
		msg := data.Message
		if msg == "" {
			msg = "N/A"
		}
		return []string{"🌍 MaxMind", escape(msg), "N/A"}
	}
	asn := normalizeASN(data.Connection.ASN)
	org := firstNonEmpty(data.Connection.Org, data.Connection.ISP, data.Connection.Domain, "N/A")
	country := joinSlash(data.CountryCode, data.Country)
	if data.Flag.Emoji != "" {
		country = data.Flag.Emoji + " " + country
	}
	return []string{
		"🌍 MaxMind",
		escape(country),
		escape(joinSlash(asn, org)),
	}
}

func formatIPInfo(info *IPInfoResponse, fallback *IPWhoResponse) []string {
	if info == nil {
		return []string{"📍 IPinfo", "N/A", "N/A"}
	}
	countryName := info.Country
	if fallback != nil && strings.EqualFold(fallback.CountryCode, info.Country) {
		countryName = fallback.Country
	}
	place := joinSlash(info.Country, countryName, info.City)
	if flag := countryFlag(info.Country); flag != "" {
		place = flag + " " + place
	}
	org := splitIPInfoOrg(info.Org)
	if info.Hostname != "" && org == "N/A" {
		org = info.Hostname
	}
	return []string{
		"📍 IPinfo",
		escape(place),
		escape(org),
	}
}

func formatCensys(ip string, censys *CensysHostResponse) []string {
	if censys == nil {
		return []string{"🔎 Censys", escape(censysHostURL + "/" + ip)}
	}
	if len(censys.Result.Services) == 0 {
		return []string{"🔎 Censys", "no indexed services"}
	}
	ports := make([]string, 0, len(censys.Result.Services))
	seen := map[string]bool{}
	for _, svc := range censys.Result.Services {
		name := strings.ToLower(firstNonEmpty(svc.ServiceName, svc.Transport))
		item := strconv.Itoa(svc.Port)
		if name != "" {
			item += "/" + name
		}
		if !seen[item] {
			seen[item] = true
			ports = append(ports, item)
		}
	}
	sort.Strings(ports)
	if len(ports) > 8 {
		ports = append(ports[:8], fmt.Sprintf("+%d more", len(ports)-8))
	}
	return []string{"🔎 Censys", escape(strings.Join(ports, ", "))}
}

func makeKeyboard(ip, asn string) *InlineKeyboardMarkup {
	if ip == "" {
		return nil
	}
	rows := [][]InlineKeyboardButton{
		{
			{Text: "🌐 bgp.he.net", URL: "https://bgp.he.net/ip/" + url.PathEscape(ip)},
			{Text: "🧭 bgp.tools", URL: "https://bgp.tools/prefix/" + url.PathEscape(ip)},
		},
		{
			{Text: "📍 ipinfo.io", URL: "https://ipinfo.io/" + url.PathEscape(ip)},
			{Text: "🔎 Censys", URL: censysHostURL + "/" + url.PathEscape(ip)},
		},
		{
			{Text: "📜 whois", URL: "https://who.is/whois/" + url.PathEscape(ip)},
		},
	}
	if asn != "" && asn != "N/A" {
		rows[2] = append(rows[2], InlineKeyboardButton{Text: "🛰 " + asn, URL: "https://bgp.he.net/" + url.PathEscape(asn)})
	}
	return &InlineKeyboardMarkup{InlineKeyboard: rows}
}

func fetchSubscriptionLines(ctx context.Context, cfg Config, rawURL string) ([]string, http.Header, error) {
	baseHeaders := map[string]string{
		"x-hwid":         cfg.HWID,
		"x-device-os":    "Linux",
		"x-ver-os":       "6.1",
		"x-device-model": "Server",
	}
	var lastHeaders http.Header
	var lastRaw string
	var lastErr error

	for _, ua := range subscriptionUAChain {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range baseHeaders {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", ua)

		resp, err := apiHTTPClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		lastHeaders = resp.Header.Clone()
		lastRaw = strings.TrimSpace(string(data))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		lines, format := parseSubscriptionBody(lastRaw)
		if len(lines) > 0 {
			log.Printf("subscription parsed as %s with UA=%q: %d lines", format, ua, len(lines))
			return lines, lastHeaders, nil
		}
	}
	if lastRaw != "" {
		lines := nonEmptyLines(lastRaw)
		if len(lines) > 0 {
			return lines, lastHeaders, nil
		}
	}
	if lastErr != nil {
		return nil, lastHeaders, lastErr
	}
	return nil, lastHeaders, errors.New("unknown subscription format")
}

func parseSubscriptionBody(raw string) ([]string, string) {
	plain := nonEmptyLines(raw)
	if containsProxyURI(plain) {
		return plain, "plain-text"
	}
	if lines := parseXrayJSON(raw); len(lines) > 0 {
		return lines, "xray-json"
	}
	if lines := tryBase64Lines(raw); len(lines) > 0 {
		return lines, "base64"
	}
	for _, line := range plain {
		if lines := tryBase64Lines(line); len(lines) > 0 {
			return lines, "base64-per-line"
		}
	}
	return nil, "unknown"
}

func nonEmptyLines(raw string) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func containsProxyURI(lines []string) bool {
	for _, line := range lines {
		lo := strings.ToLower(line)
		if strings.HasPrefix(lo, "vless://") || strings.HasPrefix(lo, "vmess://") || strings.HasPrefix(lo, "trojan://") || strings.HasPrefix(lo, "ss://") {
			return true
		}
	}
	return false
}

func tryBase64Lines(raw string) []string {
	cleaned := strings.TrimSpace(raw)
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")
	decoders := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}
	for _, enc := range decoders {
		data, err := enc.DecodeString(padBase64(cleaned))
		if err != nil {
			continue
		}
		lines := nonEmptyLines(string(data))
		if containsProxyURI(lines) {
			return lines
		}
	}
	return nil
}

func parseXrayJSON(raw string) []string {
	var data any
	if err := json.Unmarshal([]byte(raw), &data); err == nil {
		return outboundsToURIs(data)
	}
	var result []string
	for _, line := range nonEmptyLines(raw) {
		var item any
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			result = append(result, outboundsToURIs(item)...)
		}
	}
	return result
}

func outboundsToURIs(data any) []string {
	var outbounds []any
	switch v := data.(type) {
	case map[string]any:
		if raw, ok := v["outbounds"].([]any); ok {
			outbounds = raw
		} else {
			outbounds = []any{v}
		}
	case []any:
		outbounds = v
	default:
		return nil
	}
	var uris []string
	for _, raw := range outbounds {
		ob, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if uri := outboundToURI(ob); uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

func outboundToURI(ob map[string]any) string {
	proto := strings.ToLower(strAny(firstAny(ob["protocol"], ob["type"])))
	tag := strAny(firstAny(ob["tag"], ob["name"]))
	if tag == "" {
		tag = "N/A"
	}
	switch proto {
	case "vless":
		settings := mapAny(ob["settings"])
		vnext := firstMapFromList(settings["vnext"])
		user := firstMapFromList(vnext["users"])
		stream := mapAny(ob["streamSettings"])
		reality := mapAny(stream["realitySettings"])
		tls := mapAny(stream["tlsSettings"])
		address := strAny(vnext["address"])
		port := intAny(vnext["port"])
		uid := strAny(user["id"])
		params := url.Values{}
		setVal(params, "security", strAny(stream["security"]))
		setVal(params, "type", strAny(stream["network"]))
		setVal(params, "flow", strAny(user["flow"]))
		setVal(params, "sni", firstNonEmpty(strAny(reality["serverName"]), strAny(tls["serverName"])))
		setVal(params, "fp", strAny(reality["fingerprint"]))
		setVal(params, "pbk", strAny(reality["publicKey"]))
		setVal(params, "sid", strAny(reality["shortId"]))
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", uid, address, port, params.Encode(), url.QueryEscape(tag))
	case "vmess":
		settings := mapAny(ob["settings"])
		vnext := firstMapFromList(settings["vnext"])
		user := firstMapFromList(vnext["users"])
		stream := mapAny(ob["streamSettings"])
		tls := mapAny(stream["tlsSettings"])
		ws := mapAny(stream["wsSettings"])
		headers := mapAny(ws["headers"])
		vmess := map[string]string{
			"v":    "2",
			"ps":   tag,
			"add":  strAny(vnext["address"]),
			"port": strconv.Itoa(intAny(vnext["port"])),
			"id":   strAny(user["id"]),
			"net":  strAny(stream["network"]),
			"tls":  strAny(stream["security"]),
			"sni":  strAny(tls["serverName"]),
			"path": strAny(ws["path"]),
			"host": strAny(headers["Host"]),
			"type": "none",
		}
		data, _ := json.Marshal(vmess)
		return "vmess://" + base64.StdEncoding.EncodeToString(data)
	case "trojan":
		settings := mapAny(ob["settings"])
		server := firstMapFromList(settings["servers"])
		stream := mapAny(ob["streamSettings"])
		tls := mapAny(stream["tlsSettings"])
		params := url.Values{}
		setVal(params, "security", strAny(stream["security"]))
		setVal(params, "type", strAny(stream["network"]))
		setVal(params, "sni", strAny(tls["serverName"]))
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", strAny(server["password"]), strAny(server["address"]), intAny(server["port"]), params.Encode(), url.QueryEscape(tag))
	default:
		return ""
	}
}

func parseProxyURI(raw string) (Proxy, error) {
	raw = strings.TrimSpace(raw)
	lo := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lo, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(lo, "vmess://"):
		return parseVMess(raw)
	case strings.HasPrefix(lo, "trojan://"):
		return parseTrojan(raw)
	case strings.HasPrefix(lo, "ss://"):
		return parseShadowSocks(raw)
	default:
		return Proxy{}, errors.New("unsupported proxy protocol")
	}
}

func parseVLESS(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Proxy{}, err
	}
	q := u.Query()
	return Proxy{
		Proto:       "vless",
		UUID:        firstNonEmpty(u.User.Username(), "N/A"),
		Host:        firstNonEmpty(u.Hostname(), "N/A"),
		Port:        firstNonEmpty(u.Port(), "N/A"),
		Name:        fragmentName(u),
		Security:    firstNonEmpty(q.Get("security"), "N/A"),
		SNI:         firstNonEmpty(q.Get("sni"), "N/A"),
		Network:     firstNonEmpty(q.Get("type"), "N/A"),
		Path:        firstNonEmpty(q.Get("path"), "N/A"),
		Fingerprint: firstNonEmpty(q.Get("fp"), "N/A"),
		Flow:        firstNonEmpty(q.Get("flow"), "N/A"),
		PublicKey:   firstNonEmpty(q.Get("pbk"), "N/A"),
		ShortID:     firstNonEmpty(q.Get("sid"), "N/A"),
	}, nil
}

func parseTrojan(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Proxy{}, err
	}
	q := u.Query()
	return Proxy{
		Proto:       "trojan",
		UUID:        firstNonEmpty(u.User.Username(), "N/A"),
		Host:        firstNonEmpty(u.Hostname(), "N/A"),
		Port:        firstNonEmpty(u.Port(), "N/A"),
		Name:        fragmentName(u),
		Security:    firstNonEmpty(q.Get("security"), "N/A"),
		SNI:         firstNonEmpty(q.Get("sni"), "N/A"),
		Network:     firstNonEmpty(q.Get("type"), "N/A"),
		Path:        firstNonEmpty(q.Get("path"), "N/A"),
		Fingerprint: firstNonEmpty(q.Get("fp"), "N/A"),
		Flow:        "N/A",
		PublicKey:   "N/A",
		ShortID:     "N/A",
	}, nil
}

func parseVMess(raw string) (Proxy, error) {
	payload := raw[len("vmess://"):]
	data, err := decodeBase64(payload)
	if err != nil {
		return Proxy{}, err
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return Proxy{}, err
	}
	return Proxy{
		Proto:       "vmess",
		UUID:        firstNonEmpty(strAny(obj["id"]), "N/A"),
		Host:        firstNonEmpty(strAny(obj["add"]), "N/A"),
		Port:        firstNonEmpty(strAny(obj["port"]), "N/A"),
		Name:        firstNonEmpty(strAny(obj["ps"]), "N/A"),
		Security:    firstNonEmpty(strAny(obj["tls"]), "none"),
		SNI:         firstNonEmpty(strAny(obj["sni"]), "N/A"),
		Network:     firstNonEmpty(strAny(obj["net"]), "N/A"),
		Path:        firstNonEmpty(strAny(obj["path"]), "N/A"),
		Fingerprint: firstNonEmpty(strAny(obj["fp"]), "N/A"),
		Flow:        "N/A",
		PublicKey:   "N/A",
		ShortID:     "N/A",
	}, nil
}

func parseShadowSocks(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err == nil && u.Hostname() != "" {
		return Proxy{
			Proto:    "ss",
			UUID:     firstNonEmpty(u.User.String(), "N/A"),
			Host:     u.Hostname(),
			Port:     firstNonEmpty(u.Port(), "N/A"),
			Name:     fragmentName(u),
			Security: "N/A",
			Network:  "tcp",
			SNI:      "N/A",
		}, nil
	}
	payload := raw[len("ss://"):]
	if before, after, ok := strings.Cut(payload, "#"); ok {
		payload = before
		raw = "ss://" + before + "#" + after
	}
	data, err := decodeBase64(payload)
	if err != nil {
		return Proxy{}, err
	}
	decoded := string(data)
	if !strings.Contains(decoded, "@") {
		return Proxy{}, errors.New("unsupported ss uri")
	}
	u, err = url.Parse("ss://" + decoded)
	if err != nil {
		return Proxy{}, err
	}
	return Proxy{
		Proto:    "ss",
		UUID:     firstNonEmpty(u.User.String(), "N/A"),
		Host:     firstNonEmpty(u.Hostname(), "N/A"),
		Port:     firstNonEmpty(u.Port(), "N/A"),
		Name:     fragmentName(u),
		Security: "N/A",
		Network:  "tcp",
		SNI:      "N/A",
	}, nil
}

func resolveDomain(ctx context.Context, domain string, cacheTTL time.Duration) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if cached, ok := dnsCache.Get(domain); ok {
		return cached, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			ip := addr.IP.String()
			dnsCache.Set(domain, ip, cacheTTL)
			return ip, nil
		}
	}
	if len(addrs) > 0 {
		ip := addrs[0].IP.String()
		dnsCache.Set(domain, ip, cacheTTL)
		return ip, nil
	}
	return "", errors.New("no addresses")
}

func resolveHostMaybe(ctx context.Context, host string, cacheTTL time.Duration) (string, error) {
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	return resolveDomain(ctx, host, cacheTTL)
}

func extractTarget(text string) (string, string) {
	text = strings.TrimSpace(text)
	if host, _, err := net.SplitHostPort(strings.Trim(text, "[]")); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String(), "ip"
		}
		if domainRe.MatchString(host) {
			return host, "domain"
		}
	}
	if ip := net.ParseIP(strings.Trim(text, "[]")); ip != nil {
		return ip.String(), "ip"
	}
	for _, candidate := range ipv4Re.FindAllString(text, -1) {
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String(), "ip"
		}
	}
	for _, token := range strings.Fields(text) {
		token = strings.Trim(token, " \t\r\n,;()[]{}<>«»\"'")
		token = strings.TrimSuffix(token, ":")
		if host, _, err := net.SplitHostPort(token); err == nil {
			token = host
		} else if strings.Count(token, ":") == 1 {
			before, _, _ := strings.Cut(token, ":")
			if net.ParseIP(before) != nil || domainRe.MatchString(before) {
				token = before
			}
		}
		if ip := net.ParseIP(strings.Trim(token, "[]")); ip != nil {
			return ip.String(), "ip"
		}
		if domainRe.MatchString(token) {
			return strings.ToLower(domainRe.FindString(token)), "domain"
		}
	}
	if match := domainRe.FindString(text); match != "" {
		return strings.ToLower(match), "domain"
	}
	return "", ""
}

func cleanSubject(subject string) string {
	if target, _ := extractTarget(subject); target != "" {
		return target
	}
	return clampRunes(subject, 120)
}

func isReservedIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		addr.IsInterfaceLocalMulticast()
}

func isErrorEntry(p Proxy) bool {
	host := strings.ToLower(strings.TrimSpace(p.Host))
	port := strings.TrimSpace(p.Port)
	name := strings.ToLower(p.Name)
	keywords := []string{"not supported", "contact support", "app not supported", "unsupported", "register", "activate"}
	if host == "" || host == "0.0.0.0" || host == "127.0.0.1" || host == "::1" || port == "" || port == "0" || port == "1" {
		return true
	}
	for _, kw := range keywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func subscriptionRejectReason(headers http.Header) string {
	if subtle.ConstantTimeCompare([]byte(headers.Get("x-hwid-max-devices-reached")), []byte("true")) == 1 {
		return "превышен лимит устройств для этой подписки"
	}
	if subtle.ConstantTimeCompare([]byte(headers.Get("x-hwid-not-supported")), []byte("true")) == 1 {
		return "клиент не поддерживает HWID"
	}
	return "HWID не зарегистрирован или не принят сервером"
}

func asnFromBundle(bundle GeoBundle) string {
	if bundle.MaxMind == nil || !bundle.MaxMind.Success {
		return "N/A"
	}
	return normalizeASN(bundle.MaxMind.Connection.ASN)
}

func bundleFlag(bundle GeoBundle) string {
	if bundle.MaxMind != nil && bundle.MaxMind.Flag.Emoji != "" {
		return bundle.MaxMind.Flag.Emoji
	}
	if bundle.IPInfo != nil {
		return countryFlag(bundle.IPInfo.Country)
	}
	return ""
}

func countryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return ""
	}
	runes := []rune(code)
	if runes[0] < 'A' || runes[0] > 'Z' || runes[1] < 'A' || runes[1] > 'Z' {
		return ""
	}
	return string([]rune{0x1F1E6 + runes[0] - 'A', 0x1F1E6 + runes[1] - 'A'})
}

func normalizeASN(v any) string {
	switch x := v.(type) {
	case nil:
		return "N/A"
	case string:
		x = strings.TrimSpace(x)
		if x == "" || strings.EqualFold(x, "N/A") {
			return "N/A"
		}
		if strings.HasPrefix(strings.ToUpper(x), "AS") {
			return strings.ToUpper(x)
		}
		return "AS" + x
	case float64:
		if x <= 0 {
			return "N/A"
		}
		return "AS" + strconv.Itoa(int(x))
	case int:
		if x <= 0 {
			return "N/A"
		}
		return "AS" + strconv.Itoa(x)
	default:
		s := fmt.Sprint(x)
		if s == "" {
			return "N/A"
		}
		if strings.HasPrefix(strings.ToUpper(s), "AS") {
			return strings.ToUpper(s)
		}
		return "AS" + s
	}
}

func splitIPInfoOrg(org string) string {
	org = strings.TrimSpace(org)
	if org == "" {
		return "N/A"
	}
	parts := strings.Fields(org)
	if len(parts) > 1 && strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
		return parts[0] + " / " + strings.Join(parts[1:], " ")
	}
	return org
}

func userFacingWarning(warnings []string) string {
	for _, warning := range warnings {
		lo := strings.ToLower(warning)
		if strings.Contains(lo, "reserved range") || strings.Contains(lo, "reserved") || strings.Contains(lo, "bogon") {
			return "Reserved range: геолокация может быть недоступна для частного или зарезервированного адреса."
		}
	}
	return ""
}

func fragmentName(u *url.URL) string {
	if u.Fragment == "" {
		return "N/A"
	}
	name, err := url.QueryUnescape(u.Fragment)
	if err != nil {
		return u.Fragment
	}
	return firstNonEmpty(name, "N/A")
}

func joinSlash(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && part != "N/A" {
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "N/A"
	}
	return strings.Join(clean, " / ")
}

func firstNonEmpty(values ...string) string {
	for _, val := range values {
		if strings.TrimSpace(val) != "" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func escape(s string) string {
	return html.EscapeString(s)
}

func clampRunes(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	return string(rs[:max-1]) + "…"
}

func padBase64(s string) string {
	if rem := len(s) % 4; rem != 0 {
		s += strings.Repeat("=", 4-rem)
	}
	return s
}

func decodeBase64(s string) ([]byte, error) {
	decoders := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}
	var last error
	for _, enc := range decoders {
		data, err := enc.DecodeString(padBase64(s))
		if err == nil {
			return data, nil
		}
		last = err
	}
	return nil, last
}

func strAny(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return fmt.Sprint(x)
	case int:
		return strconv.Itoa(x)
	case json.Number:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func intAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		i, _ := strconv.Atoi(x)
		return i
	default:
		return 0
	}
}

func mapAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func firstMapFromList(v any) map[string]any {
	items, ok := v.([]any)
	if !ok || len(items) == 0 {
		return map[string]any{}
	}
	return mapAny(items[0])
}

func firstAny(values ...any) any {
	for _, val := range values {
		if val != nil && strAny(val) != "" {
			return val
		}
	}
	return nil
}

func setVal(values url.Values, key, value string) {
	if strings.TrimSpace(value) != "" {
		values.Set(key, value)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
