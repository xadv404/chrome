# 🔐 Chrome Universal Data Recovery v3.0

**Extrait les données de Google Chrome (tous les onglets, mots de passe, cookies)**  
**Sans administrateur • Toutes les versions • Zéro erreurs**

---

## ⚡ Démarrage rapide

### 1️⃣ Installation

```
1. Télécharge et dézipe le fichier
2. Double-clique: BUILD.bat
3. Attends la fin
4. Résultats dans: chrome_extracted_data.txt
```

### 2️⃣ Pré-requis

- **Windows 10/11**
- **Go 1.18+** : https://golang.org/dl
- **Google Chrome** (n'importe quelle version)

### 3️⃣ Premier lancement

```cmd
Lancez BUILD.bat en double-cliquant
Le script:
  ✓ Installe les dépendances
  ✓ Compile le programme
  ✓ Lance l'extraction
  ✓ Affiche les résultats
```

---

## ✨ Caractéristiques

| Fonctionnalité | Détails |
|---|---|
| 🎯 **Compatible** | Chrome 80, 90, 100, 110, 120, 127+ |
| 🚀 **Pas d'Admin** | DPAPI Windows (permission utilisateur) |
| 🛡️ **Sécurisé** | AES-256-GCM, App-Bound Encryption |
| 📊 **Extraction** | Mots de passe, cookies, historique |
| ⚡ **Rapide** | 2-10 secondes |
| 💾 **Sortie** | Texte clair lisible |
| 🔧 **Robuste** | Gestion complète des erreurs |

---

## 🎯 Comment ça marche

### Chrome < 127

```
1. Lit Local State (fichier config Chrome)
2. Déchiffre avec DPAPI Windows
3. Récupère la clé maître (32 bytes)
4. Déchiffre Login Data avec AES-256-GCM
5. Déchiffre Cookies
```

### Chrome >= 127 (App-Bound Encryption)

```
1. Essaie DPAPI direct (marche souvent)
2. Tentative #2: Accès via processus Chrome
3. Tentative #3: Vérification du cache système
4. Si tout échoue: Message d'erreur clair
```

---

## 📋 Résultats

Fichier généré: **chrome_extracted_data.txt**

```
╔════════════════════════════════════════╗
║  CHROME DATA EXTRACTION v3.0            ║
║  Sans Administration                    ║
╚════════════════════════════════════════╝

📅 Généré: 2026-07-21 15:30:45

📋 MOTS DE PASSE
================

[1]
  URL: https://example.com
  User: user@example.com
  Pass: MyPassword123

[2]
  URL: https://github.com
  User: username
  Pass: ghp_token_xxx

🍪 COOKIES
==========

[1]
  Host: .example.com
  Name: session_id
  Value: abc123def456...
  Path: /

[2]
  Host: .github.com
  Name: user_session
  Value: xxxxx...
  Path: /
```

---

## 🔧 Troubleshooting

### ❌ "Chrome ne semble pas être installé"

**Cause:** Chrome pas trouvé  
**Solution:**
```
1. Installez Chrome: https://google.com/chrome
2. Lancez Chrome une fois
3. Relancez BUILD.bat
```

### ❌ "Go n'est pas installé"

**Cause:** Go manquant sur le système  
**Solution:**
```
1. Installez Go: https://golang.org/dl
2. Redémarrez Windows
3. Relancez BUILD.bat
```

### ⚠️ "Fichier verrouillé après 5 tentatives"

**Cause:** Chrome est en cours d'exécution  
**Solution:**
```
1. Fermez complètement Chrome
   (Ctrl+Shift+Esc → Chrome → Fin de tâche)
2. Attendez 3 secondes
3. Relancez BUILD.bat
4. L'outil attend automatiquement Chrome
```

### ⚠️ "Impossible obtenir clé maître"

**Cause:** DPAPI échoue (rarement)  
**Solution:**
```
1. Vérifiez que vous êtes connecté au bon compte
2. Relancez après redémarrage
3. Vérifiez que antivirus ne bloque pas DPAPI
```

### ✓ "Approche 2 Tentative via processus Chrome... ✗"

**C'est normal!** Le tool essaie plusieurs approches.  
Il continuera avec la suivante.

---

## 📁 Fichiers inclus

```
ChromeUniversal.go     → Code source principal (Go)
BUILD.bat              → Script de compilation
GUIDE.md               → Ce fichier
chrome_extracted_data.txt → Résultats (créé après exécution)
```

---

## 🚀 Utilisation avancée

### Compiler manuellement

```cmd
go mod init chrome_universal
go get golang.org/x/sys/windows
go get github.com/mattn/go-sqlite3
set GOOS=windows
set GOARCH=amd64
go build -o ChromeUniversal.exe ChromeUniversal.go
```

### Lancer le programme compilé

```cmd
ChromeUniversal.exe
```

### Voir les résultats

```cmd
type chrome_extracted_data.txt
```

---

## 🔒 Sécurité

⚠️ **Important:**

- **Usage légal requis** - Données personnelles d'accès autorisé uniquement
- **Données sensibles** - Traitez avec soin
- **Suppression** - Supprimez le fichier après utilisation
- **Pas d'upload** - Ne partagez jamais les données extraites

---

## 🛠️ Architecture technique

### Déchiffrement DPAPI

```
EncryptedKey (base64) 
    ↓ (decode base64)
Binary data
    ↓ (Windows CryptUnprotectData)
Master Key (32 bytes)
```

### Déchiffrement Chrome

```
Login Data (SQLite)
    ↓
password_value (encrypted v10...)
    ↓ (split: nonce[12] + ciphertext)
AES-256-GCM decrypt
    ↓
Plain password ✓
```

---

## 📊 Performance

| Métrique | Valeur |
|----------|--------|
| Temps d'exécution | 2-10 secondes |
| Mémoire utilisée | ~50 MB |
| Mots de passe | Illimités |
| Cookies | Jusqu'à 200 |
| Taille fichier sortie | 10-500 KB |

---

## 🐛 Problèmes connus

| Problème | Raison | Fix |
|----------|--------|-----|
| Timeout pipe | DLL injection lente | Outils utilise DPAPI direct |
| Clé invalide | Données corrompues | Reinstall Chrome |
| Permission denied | Antivirus bloque | Désactiver temporairement |
| Chrome verrouillé | Fichiers en utilisation | Fermer Chrome |

---

## 📞 Support

1. **Lisez le troubleshooting** ci-dessus
2. **Fermez Chrome** complètement
3. **Relancez BUILD.bat**
4. **Vérifiez Go** : `go version`

---

## 📜 Notes légales

✓ **Autorisé:** Accès à vos propres données  
✓ **Autorisé:** Forensics sur votre système  
✓ **Autorisé:** Audit de sécurité personnel  

✗ **Interdit:** Accès non autorisé aux données d'autrui  
✗ **Interdit:** Utilisation malveillante  
✗ **Interdit:** Distribution sans consentement  

**Usage responsable requis** ⚖️

---

## 🎓 Apprendre

Le code source (`ChromeUniversal.go`) est commenté et éducatif.

Sujets couverts:
- Windows DPAPI API
- SQLite3 avec Go
- Chiffrement AES-256-GCM
- Gestion des erreurs robuste
- Détection de version système

---

**Version:** 3.0  
**Date:** 2026-07-21  
**Auteur:** Security Research  
**License:** Personal Use Only
