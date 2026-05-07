# PKI Management System — Master Rad

Implementacija mini PKI (Public Key Infrastructure) sistema za upravljanje 
digitalnim sertifikatima, razvijena kao praktični deo master rada.

**Tehnologije:** ASP.NET Core 9, C#, MongoDB, BouncyCastle, Swagger

---

## Arhitektura sistema

Root CA (4096-bit RSA, 20 godina)
└── Intermediate CA (2048-bit RSA, 10 godina)
└── EndEntity sertifikati (2048-bit RSA, konfigurabilan period)

CA privatni ključevi se čuvaju enkriptovano u MongoDB koristeći AES-256.

---

## Funkcionalnosti

- Generisanje RSA ključeva (1024/2048/4096-bit)
- Izdavanje X.509 v3 sertifikata sa svim ekstenzijama
- Trostepena CA hijerarhija (Root → Intermediate → EndEntity)
- Persistovanje CA ključeva sa AES-256 enkripcijom
- Opoziv sertifikata sa standardnim razlozima (RFC 5280)
- CRL generisanje potpisano od Intermediate CA
- Verifikacija lanca poverenja
- OCSP-like status endpoint
- Bulk izdavanje sertifikata
- Audit log svih operacija
- Statistike sistema
- Benchmark performansi generisanja ključeva

---

## Pokretanje projekta

### Preduslovi

- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- [MongoDB](https://www.mongodb.com/try/download/community) (lokalno na portu 27017)
- [VS Code](https://code.visualstudio.com/) sa C# Dev Kit ekstenzijom

### Instalacija

```bash
git clone https://github.com/TvojUsername/PKI-MasterRad.git
cd PKI-MasterRad/PKI.API
dotnet restore
dotnet run
```

Aplikacija se pokreće na `http://localhost:5266`.  
Swagger UI dostupan na: `http://localhost:5266`

Pri prvom pokretanju automatski se generiše PKI infrastruktura i čuva u MongoDB.  
Pri svakom sledećem pokretanju, CA se učitava iz baze — ključevi se ne regenerišu.

---

## API Endpointi

### CA — Certification Authority
| Metoda | Ruta | Opis |
|--------|------|------|
| GET | /api/Ca/root | Root CA sertifikat |
| GET | /api/Ca/intermediate | Intermediate CA sertifikat |

### Sertifikati
| Metoda | Ruta | Opis |
|--------|------|------|
| POST | /api/Certificate/issue | Izdavanje sertifikata |
| POST | /api/Certificate/issue-bulk | Bulk izdavanje |
| GET | /api/Certificate | Lista svih sertifikata |
| GET | /api/Certificate/{serial} | Detalji sertifikata |
| GET | /api/Certificate/status/{status} | Filtriranje po statusu |

### Verifikacija
| Metoda | Ruta | Opis |
|--------|------|------|
| GET | /api/Verification/verify/{serial} | Verifikacija lanca poverenja |
| POST | /api/Verification/verify-pem | Verifikacija PEM sertifikata |
| GET | /api/Verification/status/{serial} | OCSP-like status provjera |

### Opoziv
| Metoda | Ruta | Opis |
|--------|------|------|
| POST | /api/Revocation/revoke/{serial} | Opoziv sertifikata |
| GET | /api/Revocation/crl | Generisanje CRL liste |

### Statistike i audit
| Metoda | Ruta | Opis |
|--------|------|------|
| GET | /api/Statistics | Statistike sistema |
| GET | /api/Statistics/expiring | Sertifikati kojima ističe važnost |
| GET | /api/Audit | Audit log |
| GET | /api/Audit/filter?action= | Filtriranje audit loga |

### Performanse
| Metoda | Ruta | Opis |
|--------|------|------|
| GET | /api/Performance/benchmark/keygen | RSA keygen benchmark |

---

## Bezbednosne napomene

- CA privatni ključevi su enkriptovani AES-256 pre čuvanja u bazi
- U produkcijskom okruženju enkripcioni ključ bi bio u Azure Key Vault ili HSM
- EndEntity privatni ključevi se čuvaju u bazi — u produkciji bi se isporučivali 
  samo klijentu i ne bi se čuvali na serveru

---

## Struktura projekta

PKI_MasterRad/
└── PKI.API/
├── Controllers/
│   ├── AuditController.cs
│   ├── CaController.cs
│   ├── CertificateController.cs
│   ├── PerformanceController.cs
│   ├── RevocationController.cs
│   ├── StatisticsController.cs
│   └── VerificationController.cs
├── Models/
│   ├── AuditLogRecord.cs
│   ├── BulkCertificateRequest.cs
│   ├── CaKeyRecord.cs
│   └── CertificateRecord.cs
├── Services/
│   ├── AuditService.cs
│   ├── CertificateAuthorityService.cs
│   ├── CertificateService.cs
│   ├── KeyEncryptionService.cs
│   ├── MongoDbService.cs
│   ├── PerformanceService.cs
│   ├── RevocationService.cs
│   ├── StatisticsService.cs
│   └── VerificationService.cs
├── Settings/
│   └── MongoDbSettings.cs
└── Program.cs

---

## Autor

Master rad — [Marta Kornjača], [Univerzitet Singidunum], 2026.