package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
)

// main variables
var (
	user_hwid         string         // users HWID to be checked/registered etc
	user_ID           string         // user ID to be associated with the user_hwid In the database
	api_key           string         // Authcord APIKEY
	admin_key         string         // Authcord admin APIKEY
	database_password string = ""    // database password
	channel_id        string = ""    // channel for commands to be sent to
	app_hash          string         // string that contains the APP HASH / APP ID
	apphashexists     bool           // boolean for checking if apphash exists
	success           bool   = false // boolean for checking if certian values are a success or not
	valid             bool   = false // boolean for checking if an HWID is valid or not / was called "check"
	apikeyexist       bool   = false // boolean for checking if an APIKEY exists or not
	adminapikeyexist  bool   = false // boolean for checking if an admin level APIKEY exists or not
)

// Discord Tokens
var (
	tokens = []string{
		"", // token for client one
		"", // token for client two
	}
)

// structs for json responses on the REST API
type helpStruct struct {
	Login         string `json:"login"`        // endpoint and params for logging in
	Register      string `json:"register"`     // endpoint and params for registering an HWID
	Delete        string `json:"delete"`       // endpoint and params for deleting an HWID
	listhwids     string `json:"listhwids"`    // endpoint and params for listing all HWIDS you have
	genonetimekey string `json:"onetimekey`    // endpoint and params for generating a one time key
	useonetimekey string `json:"useonetimkey"` // endpoint and params for using a one timey use key
}

type listhwids struct {
	ID   string `json:"id"`   // for showing the user ID of your HWID
	HWID string `json:"hwid"` // for showing the HWID
}

type loginStruct struct {
	Response string `json:"Response"` // Response valid/invalid
}

type HomeStruct struct {
	WelcomeMsg string `json:"welcome"` // for printing out welcome message
	HelpPage   string `json:"help`     // help message
}

type RegisterStruct struct {
	Response string `json:"Response"` // Response of if the HWID was added or not
}

type DeleteStruct struct {
	Response string `json:"Response"` // Response of if the HWID was deleted or not
}

type ERROR struct {
	Response string `json:"Response"` // Response of the error
}

type useonetimekeystruct struct {
	Response string `json:"Response"` // Response of use one time key
}

type OneTimeKeyStruct struct {
	OneTimeKey string `json:"onetimekey"` // for returning the one time key you've generated
}

type NewAppHashStruct struct {
	AppHash string `json:"apphash"` // for returning the newly created apphash
}

// Functions to check if APIKEYS exist or not
func check_api_key(apikey string) {
	db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
	if err != nil {
		panic(err)
	}

	defer db.Close()

	// deactive a key if it is expired
	_, err = db.Exec("UPDATE `apikeys` SET `active` = 0 WHERE `expiration_date` < NOW();")
	if err != nil {
		panic(err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM apikeys WHERE apikey=? AND active=1", apikey).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	if count > 0 {
		apikeyexist = true
	} else {
		apikeyexist = false
	}
	db.Close()
}

func check_admin_api_key(adminkey string) {
	db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
	if err != nil {
		panic(err)
	}

	defer db.Close()

	// deactive a key if it is expired
	_, err = db.Exec("UPDATE `apikeys` SET `active` = 0 WHERE `expiration_date` < NOW();")
	if err != nil {
		log.Fatal(err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM apikeys WHERE adminkey=? AND active=1", adminkey).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	if count > 0 {
		adminapikeyexist = true
	} else {
		adminapikeyexist = false
	}

	db.Close()
}

// Function for fetching admin level key from a user level key
func get_admin_key_from_user_key(apikey string) string {
	db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
	if err != nil {
		panic(err)
	}

	defer db.Close()

	var adminkey string
	err = db.QueryRow("SELECT adminkey FROM apikeys WHERE apikey=? AND active=1", apikey).Scan(&adminkey)
	if err != nil {
		panic(err)
	}
	db.Close()

	return adminkey

}

// functions for generating and inserting an app hash
func generateAppHash() string {
	rand.Seed(time.Now().UnixNano())
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	apphash := fmt.Sprintf("%x", md5.Sum(randomBytes))
	return apphash
}

func insert_app_hash(apikey string) string {

	check_admin_api_key(apikey)
	if adminapikeyexist == false {
		return "invalid adminkey"
	} else {
		db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
		if err != nil {
			panic(err)
		}

		defer db.Close()

		// generate app hash
		apphash := generateAppHash()

		// Insert the key into the table
		_, err = db.Exec("INSERT INTO apphashes (apphash, apikey) VALUES (?, ?)", apphash, apikey)
		if err != nil {
			panic(err)
		}

		return apphash
	}
}

func check_app_hash(apphash string) {
	db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
	if err != nil {
		panic(err)
	}

	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM apphashes WHERE apphash=? ", apphash).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	if count > 0 {
		apphashexists = true
	} else {
		apphashexists = false
	}
	db.Close()
}

// functions for generating, inserting and checking one timemkeys for the generate one time key endpoint
func generate_random_key() string {
	rand.Seed(time.Now().UTC().UnixNano())

	key_length := 10 // will generate a key 10 chars long
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

	randomString := make([]rune, key_length)

	for i := range randomString {
		randomString[i] = chars[rand.Intn(len(chars))]
	}

	return string(randomString)

}

func insert_one_time_key() string {
	db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
	if err != nil {
		panic(err)
	}

	defer db.Close()

	// Generate a key string
	key := generate_random_key()

	// Insert the key into the table
	_, err = db.Exec("INSERT INTO one_time_keys (onetimekey, used) VALUES (?, ?)", key, false)
	if err != nil {
		panic(err)
	}
	return key

}

func checkonetimekey(onetimekey string) (exists, used bool, err error) {
	db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
	if err != nil {
		return false, false, err
	}
	defer db.Close()

	var count int

	query := "SELECT COUNT(*) FROM one_time_keys WHERE onetimekey = ?"
	err = db.QueryRow(query, onetimekey).Scan(&count)
	if err != nil {
		return false, false, err
	}

	if count == 0 {
		return false, false, nil
	}
	exists = true

	stmt, err := db.Prepare("SELECT used FROM one_time_keys WHERE onetimekey = ?")
	if err != nil {
		return false, false, err
	}
	defer stmt.Close()

	err = stmt.QueryRow(onetimekey).Scan(&used)
	if err != nil {
		return false, false, err
	}

	return exists, used, nil
}

// Discord functions
func response_check(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}

	if m.Content == "Valid "+user_hwid {
		valid = true
	} else if m.Content == "Invalid" {
		valid = false
	} else if m.Content == "Success "+user_hwid {
		success = true
	} else if m.Content == "Failed" {
		success = false
	}
}

func login_check(s *discordgo.Session, e *discordgo.Ready) {
	s.ChannelMessageSend(channel_id, "!check "+user_hwid+" "+admin_key+" "+app_hash)
}

func register(s *discordgo.Session, e *discordgo.Ready) {
	s.ChannelMessageSend(channel_id, "!register "+user_hwid+" "+api_key+" "+user_ID+" "+app_hash)
}

func delete_hwid(s *discordgo.Session, e *discordgo.Ready) {
	s.ChannelMessageSend(channel_id, "!delete "+user_hwid+" "+api_key+" "+app_hash)
}

// init authcord and send command based on what is asked
func authcord_start(option, hwid, apikey, userid, channel, apphash string) bool {
	rand.Seed(time.Now().UnixNano())
	token := tokens[rand.Intn(len(tokens))]

	user_hwid = hwid
	channel_id = channel
	api_key = apikey
	user_ID = userid
	app_hash = apphash

	dg, e := discordgo.New("Bot " + token)
	if e != nil {
		panic("Error Initializing Bot")
	}
	defer dg.Close()

	dg.AddHandler(response_check)
	if option == "login" {
		admin_key = get_admin_key_from_user_key(api_key)
		dg.AddHandler(login_check)
	} else if option == "register" {
		dg.AddHandler(register)
	} else if option == "delete" {
		dg.AddHandler(delete_hwid)
	} else {
		return false
	}

	dg.Identify.Intents = discordgo.IntentsGuildMessages

	e = dg.Open()
	if e != nil {
		fmt.Printf("error: %v\n", e)
	}

	var i int
	for start := time.Now(); time.Since(start) < time.Second; {
		if i == 5000 && valid == false {
			fmt.Println("Invalid")
			time.Sleep(5000)
		}
		if valid == true {
			e = dg.Close()
			if e != nil {
				fmt.Printf("error: %v\n", e)
			}

			break
		}

		time.Sleep(1000)
		i++
	}

	return true
}

// parse commands
func parse_cmd(content string, token string, start, end int) string {
	splice := strings.Split(content, token)
	for q := 0; q < 9; q++ {
		splice = append(splice, " ")
	}

	return strings.Join(splice[start:end], "")
}

// AUTCORD API ENDPOINTS
func home(w http.ResponseWriter, r *http.Request) {
	Response := HomeStruct{
		WelcomeMsg: "Welcome to the Authcord RESTAPI",
		HelpPage:   "For a tutorial read /help",
	}

	jsonResponse, _ := json.Marshal(Response)

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func Help(w http.ResponseWriter, r *http.Request) {
	response := helpStruct{
		Login:         "/api/v1/check?key={userlevelapikey}&apphash={apphash}&hwid={hwid}",
		Register:      "/api/v1/add?key={adminlevelapikey}&apphash={apphash}&hwid={hwid}&userid={userid}",
		Delete:        "/api/v1/delete?key={adminlevelapikey}&apphash={apphash}&hwid={hwid}",
		listhwids:     "/api/v1/listhwids?key={adminlevelapikey}&apphash={apphash}",
		genonetimekey: "/api/v1/generatekey?key={adminlevelapikey}",
		useonetimekey: "/api/v1/usekey?key={onetimekey}",
	}

	jsonResponse, _ := json.Marshal(response)

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func login(w http.ResponseWriter, r *http.Request) {
	api_key := html.EscapeString(r.URL.Query().Get("key"))
	ID := html.EscapeString(r.URL.Query().Get("userid"))
	hwid := r.URL.Query().Get("hwid")
	apphash := r.URL.Query().Get("apphash")

	if api_key == "" {
		response := loginStruct{
			Response: "Please enter an APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}

	check_api_key(api_key)
	if apikeyexist == false {
		response := loginStruct{
			Response: "Invalid APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}

	authcord_start(
		"login", hwid, api_key, ID, channel_id, apphash,
	)
	for {
		if valid == true {
			response := loginStruct{
				Response: "Valid",
			}
			jsonResponse, _ := json.Marshal(response)

			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonResponse)
			break
		} else if valid == false {
			response := loginStruct{
				Response: "Invalid",
			}
			jsonResponse, _ := json.Marshal(response)

			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonResponse)
			break
		}
		time.Sleep(2000)
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	api_key := html.EscapeString(r.URL.Query().Get("key"))
	ID := html.EscapeString(r.URL.Query().Get("userid"))
	hwid := r.URL.Query().Get("hwid")
	apphash := r.URL.Query().Get("apphash")

	if api_key == "" {
		response := RegisterStruct{
			Response: "Please enter an APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}

	check_admin_api_key(api_key)
	if adminapikeyexist == false {
		response := RegisterStruct{
			Response: "Invalid APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}
	authcord_start(
		"register", hwid, api_key, ID, channel_id, apphash,
	)

	for {
		if success == true {
			response := RegisterStruct{
				Response: "hwid added",
			}
			jsonResponse, _ := json.Marshal(response)

			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonResponse)
			return
		} else if success == false {
			response := RegisterStruct{
				Response: "Failed to add hwid",
			}
			jsonResponse, _ := json.Marshal(response)

			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonResponse)
			return
		}
		time.Sleep(2000)
	}

}

func delete(w http.ResponseWriter, r *http.Request) {
	api_key := html.EscapeString(r.URL.Query().Get("key"))
	ID := html.EscapeString(r.URL.Query().Get("userid"))
	hwid := r.URL.Query().Get("hwid")
	apphash := r.URL.Query().Get("apphash")

	if api_key == "" {
		response := DeleteStruct{
			Response: "Please enter an APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}

	check_admin_api_key(api_key)
	if adminapikeyexist == false {
		response := DeleteStruct{
			Response: "Invalid APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}
	authcord_start(
		"delete", hwid, api_key, ID, channel_id, apphash,
	)

	response := DeleteStruct{
		Response: "Successfully Deleted HWID",
	}
	jsonResponse, _ := json.Marshal(response)

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

// OneTimeKey endpoints
func Generate_Onetime_Key_Endpoint(w http.ResponseWriter, r *http.Request) {
	key := insert_one_time_key()
	api_key := html.EscapeString(r.URL.Query().Get("key"))

	check_admin_api_key(api_key)
	if adminapikeyexist == false {
		response := ERROR{
			Response: "Invalid APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}

	response := OneTimeKeyStruct{
		OneTimeKey: key,
	}

	jsonResponse, _ := json.Marshal(response)

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func useonetimekey(w http.ResponseWriter, r *http.Request) {
	onetimekey := html.EscapeString(r.URL.Query().Get("onetimekey"))
	exists, used, err := checkonetimekey(onetimekey)
	if err != nil {
		panic(err)
		return
	}

	if !exists || used {
		response := useonetimekeystruct{
			Response: "Invalid onetimekey",
		}
		jsonResponse, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	} else if used {
		response := useonetimekeystruct{
			Response: "Invalid onetimekey",
		}
		return
		jsonResponse, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	} else {
		db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
		if err != nil {
			panic(err)
		}
		defer db.Close()
		// Update one-time key to "used"
		_, err = db.Exec("UPDATE one_time_keys SET used = 1 WHERE onetimekey = ?", onetimekey)
		if err != nil {
			panic(err.Error())
		}

		response := useonetimekeystruct{
			Response: "Valid key",
		}

		jsonResponse, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}

}

func listHWIDS(w http.ResponseWriter, r *http.Request) {
	adminkey := html.EscapeString(r.URL.Query().Get("key"))
	db, err := sql.Open("mysql", "root:"+database_password+"@tcp(localhost:3306)/authcord")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	results, err := db.Query("SELECT id, hwid FROM logins WHERE apikey = ?", adminkey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	var logins []listhwids
	for results.Next() {
		var l listhwids
		err = results.Scan(&l.ID, &l.HWID)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		logins = append(logins, l)
	}

	jsonData, err := json.Marshal(logins)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

// endpoint for generating a new apphash
func newapphash(w http.ResponseWriter, r *http.Request) {
	api_key := html.EscapeString(r.URL.Query().Get("key"))
	apphash := insert_app_hash(api_key)

	check_admin_api_key(api_key)
	if adminapikeyexist == false {
		response := ERROR{
			Response: "Invalid APIKEY",
		}
		jsonResponse, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	} else {
		response := NewAppHashStruct{
			AppHash: apphash,
		}

		jsonResponse, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
		return
	}
}

// admin function for creating APIKEYS
func addnewkey(w http.ResponseWriter, r *http.Request) {

}

// Rate limit function
func rateLimitMiddleware(limiter *rate.Limiter) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				http.Error(w, "Too many requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	router := mux.NewRouter()
	limiter := rate.NewLimiter(10, 1)
	router.Use(rateLimitMiddleware(limiter))
	router.HandleFunc("/", home)
	router.HandleFunc("/help", Help)

	router.HandleFunc("/api/v1/check", login)
	router.HandleFunc("/api/v1/add", Register)
	router.HandleFunc("/api/v1/delete", delete)
	router.HandleFunc("/api/v1/generatekey", Generate_Onetime_Key_Endpoint)
	router.HandleFunc("/api/v1/usekey", useonetimekey)
	router.HandleFunc("/api/v1/listhwids", listHWIDS)
	router.HandleFunc("/api/v1/newapphash", newapphash)

	router.HandleFunc("/admin/v1/newkey", addnewkey)
	log.Fatal(http.ListenAndServe(":8080", router))
}
