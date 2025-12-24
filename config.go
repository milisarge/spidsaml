package spidsaml

import (
  "github.com/BurntSushi/toml"
  "log"
)

var AttributeMap = map[string]string{
        "displayName":             "urn:oid:2.16.840.1.113730.3.1.241",
        "givenName":               "urn:oid:2.5.4.42",
        "surname":                 "urn:oid:2.5.4.4",
        "cn":                      "urn:oid:2.5.4.3",
        "sn":                      "urn:oid:2.5.4.4",
        "uid":                     "urn:oid:0.9.2342.19200300.100.1.1",
        "mail":                    "urn:oid:0.9.2342.19200300.100.1.3",
        "schacPersonalUniqueCode": "urn:oid:1.3.6.1.4.1.25178.1.2.14",
        "schacHomeOrganization":   "urn:oid:1.3.6.1.4.1.25178.1.2.9",
        "eduPersonOrcid":          "urn:oid:1.3.6.1.4.1.5923.1.1.1.16",
        "eduPersonUniqueId":       "urn:oid:1.3.6.1.4.1.5923.1.1.1.13",
        "eduPersonAssurance":      "urn:oid:1.3.6.1.4.1.5923.1.1.1.11",
        "eduPersonTargetedID":     "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
        "eduPersonScopedAffiliation": "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
        "eduPersonEntitlement":    "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
        "eduPersonPrincipalName":  "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
	    "eduPersonAffiliation"  :  "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
}

type ConfigFile struct {
        IDPEntityID                string   `toml:"IDPEntityID"`
        IDPdepo			           string   `toml:"IDPdepo"`
        EntityID                   string   `toml:"EntityID"`
        KeyFile                    string   `toml:"KeyFile"`
        CertFile                   string   `toml:"CertFile"`
        AcsUrls                    []string `toml:"AcsUrls"`
        SlsUrls                    []string `toml:"SlsUrls"`
        AttributeConsumingServices []ConfigAttributeConsumingService `toml:"AttributeConsumingServices"`
}

type ConfigServiceDetails struct {
    ServiceNames []ServiceName `toml:"ServiceNames"`
    Attributes   []string      `toml:"Attributes"`
}

type ConfigAttributeConsumingService struct {
    Details ConfigServiceDetails `toml:"Details"`
}

func ConfigureSP(config_file string) *SP {
    var Config ConfigFile
	// TOML ayar dosyasını oku
    if _, err := toml.DecodeFile(config_file, &Config); err != nil {
        log.Fatalf("TOML dosyasını okuma hatası: %v", err)
    }
    // Attribute listesini oluştur
    // Ayardaki listeyi, spidsaml'in istediği formata dönüştür
    var finalAttributes []Attribute
    // İlk ACS'yi varsayıyoruz
    if len(Config.AttributeConsumingServices) > 0 {
        tomlAttrs := Config.AttributeConsumingServices[0].Details.Attributes
        for _, attrName := range tomlAttrs {
            // AttributeMap içindeki Name'i bul ve spidsaml.Attribute yapısını oluştur
            if oid, ok := AttributeMap[attrName]; ok {
              // Son alan ("true") hardcoded olarak veya TOML'dan alınabilir.
              // Örnekte hardcoded kullandık.
              finalAttributes = append(finalAttributes, Attribute{
                  FriendlyName: attrName,
                  Name:    oid,
                  IsRequired: "true",
              })
            } else {
                log.Printf("UYARI: Bilinmeyen öznitelik adı atlandı: %s", attrName)
            }
        }
    } else {
      log.Fatalf("HATA: %s içinde AttributeConsumingServices tanımlı değil.", config_file)
    }
    // 3. SP Nesnesini Oluştur
    sp := &SP{
	    IDPEntityID: Config.IDPEntityID,
	    EntityID: Config.EntityID,
	    KeyFile:  Config.KeyFile,
	    CertFile: Config.CertFile,
	    AssertionConsumerServices: Config.AcsUrls,
	    // SingleLogoutServices için binding ataması
	    SingleLogoutServices: map[string]SAMLBinding{},
	    // AttributeConsumingServices oluştur
	    AttributeConsumingServices: []AttributeConsumingService{
	        {
	            ServiceNames: Config.AttributeConsumingServices[0].Details.ServiceNames,
	            Attributes:   finalAttributes, // Dinamik olarak oluşturulan liste
	        },
	    },
    }

    // Sadece bir SLS URL'si olduğunu ve Binding'in HTTPRedirect olduğunu varsayıyoruz
    if len(Config.SlsUrls) > 0 {
        // sp nesnesinin içindeki SingleLogoutServices haritasına yeni bir giriş ekle.
        sp.SingleLogoutServices[Config.SlsUrls[0]] = HTTPRedirect
    }

	// IDP depo dizininden idp bilgilerini yükle
    err := sp.LoadIDPMetadata(Config.IDPdepo)
    if err != nil {
        log.Fatalf("Failed to load IdP metadata: %v",err)
    }
    
    return sp
}
