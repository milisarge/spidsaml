package spidsaml

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"text/template"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/rand"
	"strings"
	"fmt"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"github.com/beevik/etree"
)

type ServiceName struct {
	Lang string
	Name string
}

type Attribute struct {
	FriendlyName string
	Name         string
	IsRequired   string
}

// AttributeConsumingService defines, well, an AttributeConsumingService.
type AttributeConsumingService struct {
	ServiceNames []ServiceName
	Attributes   []Attribute
}

// Organization defines SP Organization data
type Organization struct {
	Names        []string
	DisplayNames []string
	URLs         []string
}

type ContactPerson struct {
	Email   string
	IPACode string
}

// SAMLBinding can be either HTTPRedirect or HTTPPost.
type SAMLBinding string

// Constants for SAMLBinding
const (
	HTTPRedirect SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPost     SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SP represents our Service Provider
type SP struct {
	IDPEntityID                string
	EntityID                   string
	Key                        []byte
	KeyFile                    string
	Cert                       []byte
	CertFile                   string
	//SingleSignOnService        string
	AssertionConsumerServices  []string
	SingleLogoutServices       map[string]SAMLBinding
	AttributeConsumingServices []AttributeConsumingService
	IDP                        map[string]*IDP
	_cert                      *x509.Certificate
	_key                       *rsa.PrivateKey
	Organization               Organization
	ContactPerson              ContactPerson
}

// Generate dynamic Saml ID
func generateSAMLID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Hata durumunda fallback olarak zaman damgası kullanabiliriz
		return fmt.Sprintf("_%d", time.Now().UnixNano())
	}
	// SAML ID'leri mutlaka bir harf veya "_" ile başlamalıdır.
	return fmt.Sprintf("_%x", b)
}

// CertPEM returns the certificate of this Service Provider in PEM format.
func (sp *SP) GetCertPEM() []byte {
	var block = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: sp.GetCert().Raw,
	}
	return pem.EncodeToMemory(block)
}

// decryptElement decrypts an <EncryptedData> element (from an EncryptedAssertion)
// Returns decrypted XML string (e.g. "<Assertion>...</Assertion>")
func (sp *SP) decryptElement(encData *etree.Element) (string, error) {
    if encData == nil {
        return "", errors.New("nil EncryptedData element")
    }
    
    // 1) Find EncryptedKey (may be inside ds:KeyInfo)
    encKeyEl := encData.FindElement(".//EncryptedKey")
    if encKeyEl == nil {
        // sometimes EncryptedKey is outside (under KeyInfo), try parent search
        // but we attempted descendant search, so likely absent
        return "", errors.New("EncryptedKey element not found inside EncryptedData")
    }

    // 2) Get CipherValue inside EncryptedKey -> RSA-encrypted symmetric key
    keyCipherEl := encKeyEl.FindElement(".//CipherValue")
    if keyCipherEl == nil {
        return "", errors.New("EncryptedKey/CipherValue not found")
    }
    keyCipherB64 := strings.TrimSpace(keyCipherEl.Text())
    keyCipher, err := base64.StdEncoding.DecodeString(keyCipherB64)
    if err != nil {
        return "", fmt.Errorf("base64 decode EncryptedKey CipherValue: %w", err)
    }

    // 3) Decrypt RSA-OAEP using SP private key (use SHA-1 for OAEP if DigestMethod SHA1)
    priv := sp.GetKey()
    // Determine digest algorithm: many SAML IdPs use SHA1 for RSA-OAEP DigestMethod in metadata
    // We choose SHA-1 by default (XMLEnc examples typically use SHA1 for OAEP)
    // If IdP uses different digest, this may fail.
    digest := sha1.New() // or sha256.New() if metadata says so
    // rsa.DecryptOAEP requires a rand.Reader but we use nil for label and crypto/rand for randomness
    symKey, err := rsa.DecryptOAEP(digest, rand.Reader, priv, keyCipher, nil)
    if err != nil {
        return "", fmt.Errorf("rsa.DecryptOAEP failed: %w", err)
    }

    // 4) Get EncryptedData CipherValue (the actual encrypted assertion bytes)
    dataCipherEl := encData.FindElement(".//CipherValue")
    if dataCipherEl == nil {
        return "", errors.New("EncryptedData/CipherValue not found")
    }
    dataB64 := strings.TrimSpace(dataCipherEl.Text())
    encBytes, err := base64.StdEncoding.DecodeString(dataB64)
    if err != nil {
        return "", fmt.Errorf("base64 decode EncryptedData cipher: %w", err)
    }

    // 5) Try AES-GCM (xmlenc11#aes128-gcm or aes256-gcm)
    // For AES-GCM we expect: encBytes = IV(12) || ciphertext || tag(16) OR encBytes = ciphertext||tag with IV elsewhere.
    // Many IdPs use IV||ciphertext||tag; we'll attempt with IV=12, tag=16.
    var plain []byte
    tryGCM := func(key []byte, data []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        gcm, err := cipher.NewGCM(block)
        if err != nil {
            return nil, err
        }
        if len(data) < gcm.NonceSize()+gcm.Overhead() {
            return nil, errors.New("encrypted data too short for GCM")
        }
        nonce := data[:gcm.NonceSize()]
        ciphertextAndTag := data[gcm.NonceSize():] // includes tag at end
        return gcm.Open(nil, nonce, ciphertextAndTag, nil)
    }

    // Try with symmetric key sizes appropriate for AES-128/256
    // Use symKey directly if length matches. If symKey longer (e.g. 32) it's AES-256, if 16 -> AES-128
    if len(symKey) == 16 || len(symKey) == 24 || len(symKey) == 32 {
        if p, err := tryGCM(symKey, encBytes); err == nil {
            plain = p
        } else {
            // try fallback with assuming ciphertext format maybe tag appended etc; but tryGCM already uses standard format
            plain = nil
        }
    } else {
        // If symmetric key length is unexpected, try using only first 16 or 32 bytes
        if len(symKey) >= 16 {
            if p, err := tryGCM(symKey[:16], encBytes); err == nil {
                plain = p
            }
        }
        if plain == nil && len(symKey) >= 32 {
            if p, err := tryGCM(symKey[:32], encBytes); err == nil {
                plain = p
            }
        }
    }

    // 6) If GCM failed, try AES-CBC fallback (IV 16 bytes then ciphertext, PKCS7 padding)
    if plain == nil {
        // Try AES-CBC: IV=first16, ct=rest
        tryCBC := func(key []byte, data []byte) ([]byte, error) {
            if len(data) < aes.BlockSize {
                return nil, errors.New("encrypted data too short for CBC")
            }
            iv := data[:aes.BlockSize]
            ct := data[aes.BlockSize:]
            block, err := aes.NewCipher(key)
            if err != nil {
                return nil, err
            }
            if len(ct)%aes.BlockSize != 0 {
                return nil, errors.New("ciphertext not a multiple of block size")
            }
            mode := cipher.NewCBCDecrypter(block, iv)
            out := make([]byte, len(ct))
            mode.CryptBlocks(out, ct)
            // remove PKCS7 padding
            l := len(out)
            if l == 0 {
                return nil, errors.New("decrypted empty")
            }
            pad := int(out[l-1])
            if pad <= 0 || pad > aes.BlockSize || pad > l {
                return nil, errors.New("invalid padding")
            }
            for i := l - pad; i < l; i++ {
                if out[i] != byte(pad) {
                    return nil, errors.New("invalid padding bytes")
                }
            }
            return out[:l-pad], nil
        }

        // try key sizes similar to above
        if len(symKey) >= 16 {
            // try first 16 bytes
            if p, err := tryCBC(symKey[:16], encBytes); err == nil {
                plain = p
            } else if len(symKey) >= 32 {
                if p2, err2 := tryCBC(symKey[:32], encBytes); err2 == nil {
                    plain = p2
                } else {
                    // both failed
                    _ = err // ignore
                }
            }
        }
    }

    if plain == nil {
        return "", errors.New("failed to decrypt EncryptedData with GCM or CBC using decrypted symmetric key")
    }

    // plain should be the decrypted XML bytes (e.g. <Assertion>...</Assertion>)
    return string(plain), nil
}

// Cert returns the certificate of this Service Provider.
func (sp *SP) GetCert() *x509.Certificate {
	if sp._cert == nil {
		if len(sp.Cert) == 0 {
			// read file as a byte array
			var err error
			sp.Cert, err = os.ReadFile(sp.CertFile)
			if err != nil {
				panic(err)
			}
		}

		block, _ := pem.Decode(sp.Cert)
		if block == nil || block.Type != "CERTIFICATE" {
			panic("failed to parse certificate PEM")
		}
		sp.Cert = []byte{}

		var err error
		sp._cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
	}
	return sp._cert
}

// Key returns the private key of this Service Provider
func (sp *SP) GetKey() *rsa.PrivateKey {
	if sp._key == nil {
		if len(sp.Key) == 0 {
			// read file as a byte array
			var err error
			sp.Key, err = os.ReadFile(sp.KeyFile)
			if err != nil {
				panic(err)
			}
		}

		block, _ := pem.Decode(sp.Key)
		if block == nil {
			panic("failed to parse private key from PEM file " + sp.KeyFile)
		}
		sp.Key = []byte{}

		var err error

		switch block.Type {
		case "RSA PRIVATE KEY":
			sp._key, err = x509.ParsePKCS1PrivateKey(block.Bytes)

		case "PRIVATE KEY":
			var keyOfSomeType interface{}
			keyOfSomeType, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			var ok bool
			sp._key, ok = keyOfSomeType.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("file " + sp.KeyFile + " does not contain an RSA private key")
			}
		default:
			err = errors.New("unknown key type " + block.Type)
		}

		if err != nil {
			panic(err)
		}
	}
	return sp._key
}

// KeyPEM returns the private key of this Service Provider in PEM format
func (sp *SP) GetKeyPEM() []byte {
	key := sp.GetKey()
	var block = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(block)
}

// GetIDP returns an IDP object representing the Identity Provider matching the given entityID.
func (sp *SP) GetIDP(entityID string) (*IDP, error) {
	if value, ok := sp.IDP[entityID]; ok {
		return value, nil
	}
	return nil, errors.New("IdP not found")
}

// Metadata generates XML metadata of this Service Provider.
func (sp *SP) Metadata() string {
    validUntil := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05Z")
	const tmpl = `<md:EntityDescriptor 
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"  
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="{{.EntityID}}"
    validUntil="{{.VU}}"
    ID="{{.ID}}">

	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" />

    <md:SPSSODescriptor
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"  
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true">

        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
                <ds:X509Data>
                    <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate> 
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>

        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>

        {{ range $url, $binding := .SingleLogoutServices }}
        <md:SingleLogoutService 
            Binding="{{ $binding }}"
            Location="{{ $url }}" /> 
        {{ end }}

        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat> 

        {{ range $index, $url := .AssertionConsumerServices }}
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"  
            Location="{{ $url }}"
            index="{{ $index }}"
            isDefault="{{ if gt $index 0 }}false{{ else }}true{{ end }}" /> 
        {{ end }}

        {{ range $index, $attcs := .AttributeConsumingServices }}
        <md:AttributeConsumingService index="{{ $index }}"> 
            {{ range $service := $attcs.ServiceNames }}
            <md:ServiceName xml:lang="{{ $service.Lang }}">{{ $service.Name }}</md:ServiceName>
            {{ end }}
            {{ range $attr := $attcs.Attributes }}
            <md:RequestedAttribute Name="{{ $attr.Name }}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="{{ $attr.FriendlyName }}" isRequired="{{ $attr.IsRequired }}"/>
            {{ end }}
        </md:AttributeConsumingService>
        {{ end }}

    </md:SPSSODescriptor> 


</md:EntityDescriptor>
`

	var ID = generateSAMLID()
	aux := struct {
		ID string
		VU string
		*SP
		Cert string
	}{
		ID,
                validUntil,
		sp,
		base64.StdEncoding.EncodeToString(sp.GetCert().Raw),
	}

	t := template.Must(template.New("metadata").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, aux)
	//fmt.Printf("metadata:%s\n",metadata.Bytes())
	signedDoc, err := SignXML(metadata.Bytes(), sp)
	if err != nil {
		os.Stderr.WriteString("Metadata signature failed: " + err.Error() + "\n")
		signedDoc = metadata.Bytes()
	}
	return string(signedDoc)
}

func (sp *SP) GetSigningContext() *dsig.SigningContext {
	// Prepare key and certificate
	keyPair, err := tls.X509KeyPair(sp.GetCertPEM(), sp.GetKeyPEM())
	if err != nil {
		panic(err)
	}
	keyStore := dsig.TLSCertKeyStore(keyPair)

	ctx := dsig.NewDefaultSigningContext(keyStore)
	ctx.IdAttribute = "ID"
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	return ctx
}
