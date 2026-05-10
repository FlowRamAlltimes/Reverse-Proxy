package main

import (
	"database/sql"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)

type ClientLoader struct {
	limiter    *rate.Limiter
	timestamp  time.Time
	violations int
}

type loadBalancer struct {
	RealUrl           string
	ActiveConnections int
}

type IPLimiter struct {
	ips map[string]*ClientLoader
	r   rate.Limit
	b   int
}

var (
	info = []*loadBalancer{
		{"http://localhost:8001", 0}, // first api
		{"http://localhost:8002", 0}, // second api
	}
	cl = &http.Client{ // client with timeout
		Timeout: 10 * time.Second,
	}
	i = &IPLimiter{
		r:   10,
		b:   5,
		ips: make(map[string]*ClientLoader),
	}
	mu       sync.RWMutex
	banned   map[string]int // bool weights more than empty struct{} but easier idk
	Database *sql.DB
	Query    string = `
	CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    ip TEXT,
    reason TEXT
);`
	Q              string = `INSERT INTO bans(timestamp, ip, reason) VALUES(?, ?, ?)`
	InsertIntoBans *sql.Stmt
	Prp            *sql.Stmt
)

func main() {
	var err error
	banned = make(map[string]int)
	mux := http.NewServeMux()

	Database, err = sql.Open("sqlite", "reject.db")
	if err != nil {
		log.Println(err)
		return
	}

	_, err = Database.Exec(Query)
	if err != nil {
		log.Println(err)
		return
	}

	UploadMap()

	InsertIntoBans, err = Database.Prepare(Q) // for ban
	if err != nil {
		log.Printf("Error of prepareing DB %v", err)
		return
	}
	defer InsertIntoBans.Close()

	Prp, err = Database.Prepare("DELETE FROM bans WHERE timestamp < ?") // for unban
	if err != nil {
		log.Printf("Error of prepareing DB %v", err)
		return
	}
	defer Prp.Close()

	s := &http.Server{
		Handler:      mux,
		Addr:         ":8000",
		IdleTimeout:  30 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("Reverse Proxy protects:", info[0].RealUrl, info[1].RealUrl)

	go func() {
		for {
			err = Janitor()
			if err != nil {
				log.Println(err)
			}
			time.Sleep(5 * time.Minute)
		}
	}()

	mux.HandleFunc("/", proxyHandler)
	s.ListenAndServe()
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	rawIP := r.RemoteAddr
	ip, _, _ := net.SplitHostPort(rawIP)

	exists := BanTest(w, ip)
	if exists {
		log.Printf("[%s] Wanted to entry server but was detected\n", ip)
		return
	}

	var err error
	var tmpUrl string
	var tmpIndex int

	limiter := i.GetLimiter(ip)

	if !limiter.Allow() {
		mu.Lock()
		i.ips[ip].violations++
		mu.Unlock()
		log.Printf("[%s] Spam detected!\n", ip)
		if i.ips[ip].violations > 2 {
			reason := "Spam"
			err = AddToBans(ip, reason)
			if err != nil {
				log.Println(err)
				http.Error(w, "Spam", http.StatusTooManyRequests)
				log.Printf("[%s] Target has kicked due to %v\n", ip, err)
				return
			} else {
				log.Printf("[%s] Target has banned\n", ip)
				return
			}
		} else if i.ips[ip].violations <= 2 {
			http.Error(w, "Spam", http.StatusTooManyRequests)
			log.Printf("[%s] Target has kicked\n", ip)
			return
		}
	}

	if info[0].ActiveConnections == info[1].ActiveConnections {
		mu.Lock()
		tmpUrl = info[0].RealUrl
		tmpIndex = 0
		info[0].ActiveConnections++
		mu.Unlock()
	} else if info[0].ActiveConnections > info[1].ActiveConnections {
		mu.Lock()
		tmpUrl = info[1].RealUrl
		tmpIndex = 1
		info[1].ActiveConnections++
		mu.Unlock()
	} else if info[0].ActiveConnections < info[1].ActiveConnections {
		mu.Lock()
		tmpUrl = info[0].RealUrl
		tmpIndex = 0
		info[0].ActiveConnections++
		mu.Unlock()
	}
	full := tmpUrl + r.URL.Path
	if r.URL.RawQuery != "" {
		full += "?" + r.URL.RawQuery
	}

	log.Printf("[%s] We got new request [%s] : %s\n", r.Method, ip, r.URL.Path)

	newReq, err := http.NewRequest(r.Method, full, r.Body) // changes destenation
	if err != nil {
		log.Println(ip, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		mu.Lock()
		info[tmpIndex].ActiveConnections--
		mu.Unlock()
		return
	}
	defer newReq.Body.Close()

	for k, v := range r.Header {
		newReq.Header[k] = v
	}

	resp, err := cl.Do(newReq)
	if err != nil {
		log.Println(ip, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		mu.Lock()
		info[tmpIndex].ActiveConnections--
		mu.Unlock()
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println(ip, err)
		mu.Lock()
		info[tmpIndex].ActiveConnections--
		mu.Unlock()
		return
	}
	mu.Lock()
	info[tmpIndex].ActiveConnections--
	mu.Unlock()
}

func BanTest(w http.ResponseWriter, ip string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, exists := banned[ip]
	if exists {
		http.Error(w, "You are banned!\n", http.StatusForbidden)
		return true
	}

	return false
}

func AddToBans(ip string, reason string) error {
	_, err := InsertIntoBans.Exec(time.Now().Unix(), ip, reason)
	if err != nil {
		return err
	}

	mu.Lock()
	banned[ip] = int(time.Now().Unix())
	mu.Unlock()
	return nil
}

func (i *IPLimiter) GetLimiter(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	_, exists := i.ips[ip]
	if !exists {
		i.ips[ip] = &ClientLoader{
			limiter: rate.NewLimiter(i.r, i.b),
		}
	}
	return i.ips[ip].limiter
}

func Janitor() error {
	var err error
	quer := time.Now().Unix() - int64(86400)

	_, err = Prp.Exec(quer)
	if err != nil {
		return nil
	}
	log.Printf("Database has cleaned\n")

	mu.Lock()
	for ip, ts := range banned {
		if ts < int(quer) {
			delete(banned, ip)
			log.Printf("[%s] Unbanned by janitor\n", ip)
		}
	}
	mu.Unlock()

	return nil
}

func UploadMap() error {
	rows, err := Database.Query("SELECT timestamp, ip FROM bans ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			ip     string
			timest int
		)

		err := rows.Scan(&timest, &ip)
		if err != nil {
			return err
		}

		mu.Lock()
		banned[ip] = timest
		if timest < int(time.Now().Unix())-86400 {
			delete(banned, ip)
		}
		mu.Unlock()
	}
	log.Printf("Maps filled successfully\n")
	return nil
}
