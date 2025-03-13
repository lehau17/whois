package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/lissy93/who-dat/api"
	"github.com/lissy93/who-dat/lib"
	shlin "github.com/shlin168/go-whois/whois"
)

//go:embed dist/*
var staticAssets embed.FS

func main() {
	// Create a sub-directory filesystem from the embedded files
	subFS, err := fs.Sub(staticAssets, "dist")
	if err != nil {
		log.Fatal(err)
	}

	// Create a file server for the sub-directory filesystem
	embeddedServer := http.FileServer(http.FS(subFS))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		if path == "docs" {
			http.ServeFile(w, r, "dist/docs.html")
			return
		}

		// Serve embedded static files for the root
		if path == "" {
			embeddedServer.ServeHTTP(w, r)
			return
		}

		// Serve embedded static files if path starts with "assets"
		if strings.HasPrefix(path, "assets") {
			embeddedServer.ServeHTTP(w, r)
			return
		}

		// Wrap API handlers with auth middleware
		if path == "multi" {
			lib.AuthMiddleware(api.MultiHandler).ServeHTTP(w, r)
		} else {
			trimmedPath := strings.TrimPrefix(r.URL.Path, "/")
			trimmedPath = strings.TrimPrefix(trimmedPath, "http://")
			trimmedPath = strings.TrimPrefix(trimmedPath, "http:/")
			trimmedPath = strings.TrimPrefix(trimmedPath, "https://")
			trimmedPath = strings.TrimPrefix(trimmedPath, "https:/")
			trimmedPath = strings.TrimPrefix(trimmedPath, "www.")
			trimmedPath = strings.TrimSuffix(trimmedPath, "/")
			fmt.Printf("check path luc sau: %s\n", trimmedPath)

			// Cập nhật request với path mới
			r.URL.Path = "/" + trimmedPath

			fmt.Printf("check path luc sau: %s\n", r.URL.Path)

			lib.AuthMiddleware(api.MainHandler).ServeHTTP(w, r)
		}
	})
	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Check API called")

		// Lấy giá trị query param "domain"
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, `{"error": "Missing domain parameter"}`, http.StatusBadRequest)
			return
		}

		// Loại bỏ tiền tố http://, https://, www.
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.TrimPrefix(domain, "https://")
		domain = strings.TrimPrefix(domain, "www.")
		domain = strings.TrimSuffix(domain, "/")

		// Kiểm tra nếu domain vẫn không hợp lệ (không chứa dấu chấm)
		if !strings.Contains(domain, ".") {
			http.Error(w, `{"error": "Invalid domain name"}`, http.StatusBadRequest)
			return
		}

		// Tạo WHOIS client
		ctx := context.Background()
		client, err := shlin.NewClient()
		if err != nil {
			http.Error(w, `{"error": "Failed to create WHOIS client"}`, http.StatusInternalServerError)
			return
		}

		// Truy vấn WHOIS
		whoisDomain, err := client.Query(ctx, domain)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "Failed to query WHOIS: %v"}`, err), http.StatusInternalServerError)
			return
		}
		var contacts interface{}
		var abuseEmail string
		if whoisDomain.ParsedWhois != nil {
			if whoisDomain.ParsedWhois.Contacts != nil {
				if whoisDomain.ParsedWhois.Contacts.Registrant != nil {
					contacts = whoisDomain.ParsedWhois.Contacts.Registrant.Email
				}
			}
			if whoisDomain.ParsedWhois.Registrar != nil {
				abuseEmail = whoisDomain.ParsedWhois.Registrar.AbuseContactEmail
			}
		}

		// Định dạng dữ liệu trả về
		response := map[string]any{
			"domain":       domain,
			"whois_server": whoisDomain.WhoisServer,
			"contacts":     contacts,
			"abuse_email":  abuseEmail,
			"is_available": whoisDomain.IsAvailable,
		}

		// Trả về JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Choose the port to start server on
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	serverAddress := fmt.Sprintf(":%s", port)

	asciiArt := `
__          ___             _____        _  ___
\ \        / / |           |  __ \      | ||__ \
 \ \  /\  / /| |__   ___   | |  | | __ _| |_  ) |
  \ \/  \/ / | '_ \ / _ \  | |  | |/ _` + "`" + ` | __|/ /
   \  /\  /  | | | | (_) | | |__| | (_| | |_|_|
    \/  \/   |_| |_|\___/  |_____/ \__,_|\__(_)
`
	log.Println(asciiArt)
	log.Printf("\nWelcome to Who-Dat - WHOIS Lookup Service.\nApp up and running at %s", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, nil))
}
