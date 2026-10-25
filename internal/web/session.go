package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// sessionCookieName 会话 Cookie 名，与 Java 版 Jetty 默认保持一致，便于升级后浏览器无感续期。
const sessionCookieName = "JSESSIONID"

// Session 控制台登录会话（仅保存在内存，重启即失效）。
type Session struct {
	ID       string
	UID      int64
	Username string
	Role     string

	expires time.Time
}

// SessionStore 内存会话表：滑动过期 + 定时清理。
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	timeout  time.Duration
	done     chan struct{}
	stopOnce sync.Once
}

// newSessionStore 创建会话表并启动清理协程。
func newSessionStore(timeout time.Duration) *SessionStore {
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	s := &SessionStore{
		sessions: make(map[string]*Session),
		timeout:  timeout,
		done:     make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Create 新建会话并返回（登录成功后调用；同一次登录必然换新 ID，防会话固定攻击）。
func (s *SessionStore) Create(uid int64, username, role string) *Session {
	sess := &Session{
		ID:       newSessionID(),
		UID:      uid,
		Username: username,
		Role:     role,
		expires:  time.Now().Add(s.timeout),
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

// Get 按 ID 取会话并顺延过期时间；不存在或已过期返回 nil。
func (s *SessionStore) Get(id string) *Session {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	now := time.Now()
	if now.After(sess.expires) {
		delete(s.sessions, id)
		return nil
	}
	sess.expires = now.Add(s.timeout)
	return sess
}

// Destroy 销毁会话（退出登录、账号不可用）。
func (s *SessionStore) Destroy(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// Close 停止清理协程。
func (s *SessionStore) Close() {
	s.stopOnce.Do(func() { close(s.done) })
}

// cleanupLoop 周期清理过期会话，避免长期运行内存无限增长。
func (s *SessionStore) cleanupLoop() {
	interval := s.timeout
	if interval > time.Minute {
		interval = time.Minute
	}
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for id, sess := range s.sessions {
				if now.After(sess.expires) {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// newSessionID 生成 32 字节随机十六进制会话编号。
func newSessionID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败极罕见；退化为纳秒时间戳，仍能保证唯一性
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(buf)
}
