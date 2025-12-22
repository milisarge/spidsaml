package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"github.com/milisarge/spidsaml"
	"github.com/BurntSushi/toml"
	"log"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var sp *spidsaml.SP
var sp2 *spidsaml.SP

type ConfigFile struct {
	Port                       string
	IDPEntityID                string
	EntityID                   string
	KeyFile                    string
	CertFile                   string
	AcsUrls                    []string `toml:"AcsUrls"`
	SlsUrls                    []string `toml:"SlsUrls"`
	// AttributeConsumingServices, TOML'daki array of tables yapısını yansıtır.
	AttributeConsumingServices []ConfigAttributeConsumingService
}

type ConfigServiceDetails struct {
    ServiceNames []spidsaml.ServiceName `toml:"ServiceNames"`
    Attributes   []string               `toml:"Attributes"`
}

type ConfigAttributeConsumingService struct {
    // TOML'daki [AttributeConsumingServices.Details] tablosunu okuyacak
    Details ConfigServiceDetails `toml:"Details"`
}

// Global olarak tanımlanan ve kullanılacak olan konfigurasyon nesnesi
var Config ConfigFile

// JWT imza
const jwtSecret = "cokgizlibirparolmjwticin"

// JWT yapısı
type SpidClaims struct {
    UserID  string `json:"uid"`
    Name    string `json:"name"`
    Surname string `json:"surname"`
    Mail    string `json:"email"`
    // Standart JWT alanları (son kullanma tarihi, yayınlanma zamanı vb.)
    jwt.RegisteredClaims
}

var spidSession *spidsaml.Session
var authnReqID, logoutReqID string

type Template struct {
    templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
    return t.templates.ExecuteTemplate(w, name, data)
}

func main() {

    // 1. TOML dosyasını oku
	if _, err := toml.DecodeFile("settings.toml", &Config); err != nil {
		log.Fatalf("TOML dosyasını okuma hatası: %v", err)
	}
	// 2. spidsaml.Attribute listesini oluştur
	// TOML'dan okunan string array'ini, spidsaml'in istediği formata dönüştür
	var finalAttributes []spidsaml.Attribute
	// İlk ve tek ACS'yi varsayıyoruz
	if len(Config.AttributeConsumingServices) > 0 {
	  tomlAttrs := Config.AttributeConsumingServices[0].Details.Attributes
	  for _, attrName := range tomlAttrs {
	  // AttributeMap içindeki Name'i bul ve spidsaml.Attribute yapısını oluştur
	    if oid, ok := spidsaml.AttributeMap[attrName]; ok {
	    // Son alan ("true") hardcoded olarak veya TOML'dan alınabilir.
	    // Örnekte hardcoded kullandık.
	      finalAttributes = append(finalAttributes, spidsaml.Attribute{
		FriendlyName: attrName,
		Name:    oid,
		IsRequired: "true",
	      })
	    } else {
		log.Printf("UYARI: Bilinmeyen öznitelik adı atlandı: %s", attrName)
	    }
	  }
	} else {
		log.Fatal("HATA: config.toml içinde AttributeConsumingServices tanımlı değil.")
	}
	// 3. SP Nesnesini Oluştur
	sp = &spidsaml.SP{
		EntityID: Config.EntityID,
		KeyFile:  Config.KeyFile,
		CertFile: Config.CertFile,
		AssertionConsumerServices: Config.AcsUrls,
		// SingleLogoutServices için binding ataması
		SingleLogoutServices: map[string]spidsaml.SAMLBinding{},
		// AttributeConsumingServices oluştur
		AttributeConsumingServices: []spidsaml.AttributeConsumingService{
		  {
			ServiceNames: Config.AttributeConsumingServices[0].Details.ServiceNames,
			Attributes:   finalAttributes, // Dinamik olarak oluşturulan liste
		  },
		},
	}

    // Sadece bir SLS URL'si olduğunu ve Binding'in HTTPRedirect olduğunu varsayıyoruz
	if len(Config.SlsUrls) > 0 {
      // sp nesnesinin içindeki SingleLogoutServices haritasına yeni bir giriş ekle.
      sp.SingleLogoutServices[Config.SlsUrls[0]] = spidsaml.HTTPRedirect
    }

	// Load Identity Providers from their XML metadata
	err := sp.LoadIDPMetadata("./idp_depo")
	if err != nil {
		fmt.Print("Failed to load IdP metadata: ")
		fmt.Println(err)
		return
	}

	// Web framework
	t := &Template{
          templates: template.Must(
          template.New("").Funcs(template.FuncMap{
            "add": func(a, b int) int { return a + b },
            //"formatTime": func(i int64) time.Time { return fileTimeToUTC(i) },
            //"adjustTime": addTimeDelta,
          }).ParseGlob("templates/*.html")),
        }
        // */
	e := echo.New()
	e.Static("/static", "static")
	e.Use(middleware.Recover())
	e.Renderer = t
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "${time_rfc3339} | ${remote_ip} | ${method} ${uri} | ${status} | ${latency_human}\n",
	}))
	// Rotalar
	e.GET("/",spidLogin)
	e.GET("/anasayfa", ProtectedPageHandler, JWTMiddleware)
	e.GET("/metadata",metadata)
	e.POST("/acs",spidSSO)
	e.GET("/logout",spidLogout)
	e.GET("/sls",spidSLO)

	fmt.Printf("Web application listening on port:%s\n", Config.Port)
	e.Logger.Fatal(e.Start(":"+Config.Port))
}

// This endpoint exposes our metadata
func metadata(c echo.Context) error {
    c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationXML)
    return c.String(http.StatusOK, sp.Metadata())
}

// This endpoint initiates SSO through the user-chosen Identity Provider.
func _spidLogin(c echo.Context) error {
    // Check that we have the mandatory 'idp' parameter and that it matches
    // an available Identity Provider.
    idp_param := c.QueryParam("idp")
    idp, err := sp.GetIDP(idp_param)
    if err != nil {
	return c.HTML(http.StatusBadRequest, "Invalid IdP selected")
    }
    // Craft the AuthnRequest.
    authnreq := sp.NewAuthnRequest(idp)
    authnreq.AcsURL = Config.AcsUrls[0]

    authnreq.AcsIndex = 0
    authnreq.AttrIndex = 0
    authnreq.Level = 1

    // Save the ID of the Authnreq so that we can check it in the response
    // in order to prevent forgery.
    authnReqID = authnreq.ID

    // We use redirecting method, IdP using its HTTP-Redirect binding.
    // http.StatusSeeOther (303)
    redirectURL := authnreq.RedirectURL()
    return c.Redirect(http.StatusSeeOther, redirectURL)
}

func spidLogin(c echo.Context) error {
    // Check that we have the mandatory 'idp' parameter and that it matches
    // an available Identity Provider.
    // idp_depo altındaki metadata xml içindeki entityID
    idp, err := sp.GetIDP(sp.IDPEntityID)
    if err != nil {
	return c.HTML(http.StatusBadRequest, "Invalid IdP selected")
    }
    // Craft the AuthnRequest.
    authnreq := sp.NewAuthnRequest(idp)
    authnreq.AcsURL = Config.AcsUrls[0]

    authnreq.AcsIndex = 0
    authnreq.AttrIndex = 0
    authnreq.Level = 1

    // Save the ID of the Authnreq so that we can check it in the response
    // in order to prevent forgery.
    authnReqID = authnreq.ID

    // We use redirecting method, IdP using its HTTP-Redirect binding.
    // http.StatusSeeOther (303)
    redirectURL := authnreq.RedirectURL()
    return c.Redirect(http.StatusSeeOther, redirectURL)
}

// This endpoint exposes an AssertionConsumerService for our Service Provider.
// During SSO, the Identity Provider will redirect user to this URL POSTing
// the resulting assertion.
func spidSSO(c echo.Context) error {
    // Clear the ID of the outgoing Authnreq, since in this demo we're using a
    // global variable for it.
    defer func() { authnReqID = "" }()

    // Parse and verify the incoming assertion.
    response, err := spidsaml.ParseResponse(c.Request(), sp)

    if err != nil {
	fmt.Printf("Bad Response received: %s\n", err)
	return c.HTML(http.StatusBadRequest, err.Error())
    }

    // Validate the response, matching the ID of the authentication request
    err = response.Validate(authnReqID)

    if err != nil {
	fmt.Printf("Bad Response received: %s\n", err)
	return c.HTML(http.StatusBadRequest, err.Error())
    }

    if response.Success() {
	    spidSession = response.Session()
	    expirationTime := time.Now().Add(300 * time.Second)
        claims := &SpidClaims{
            UserID: spidSession.Attributes["uid"],
            Name:   spidSession.Attributes["givenName"],
            Surname:   spidSession.Attributes["sn"],
            Mail:   spidSession.Attributes["mail"],
            RegisteredClaims: jwt.RegisteredClaims{
                ExpiresAt: jwt.NewNumericDate(expirationTime),
                IssuedAt:  jwt.NewNumericDate(time.Now()),
                Subject:   spidSession.Attributes["uid"],
            },
        }
        // 2. Token Oluştur ve İmzala
        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString([]byte(jwtSecret))
        if err != nil {
            fmt.Printf("JWT imzalama hatası: %s\n", err)
            return c.String(http.StatusInternalServerError, "Token oluşturulamadı.")
        }
	    // 3. Token'ı HTTP Only Çerezine (Cookie) Göm
        cookie := new(http.Cookie)
        cookie.Name = "auth_token"
        cookie.Value = tokenString
        //cookie.Expires = expirationTime
        cookie.HttpOnly = true // JavaScript ile erişimi engelle XSS için
        cookie.Secure = true   // Yalnızca HTTPS 
        cookie.Path = "/"      // Tüm site için geçerli

        c.SetCookie(cookie)

        // 4. Kullanıcıyı yönlendir
	    return c.Redirect(http.StatusSeeOther, "anasayfa")
    
    } else {
	    fmt.Printf("Authentication Failed: %s (%s)\n",
	    response.StatusMessage(), response.StatusCode2())
	    // 401 veya 400 durum kodu
	    return c.String(http.StatusUnauthorized, response.StatusMessage()) 
    }
}

func JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// 1. Çerezi oku
		cookie, err := c.Cookie("auth_token")
		if err != nil {
			c.Set("auth", false)
			return next(c)
			//return c.String(http.StatusUnauthorized, "Giriş yapılmamış.")
		}

		tokenString := cookie.Value
		claims := &SpidClaims{}

		// 2. Token'ı Parse Et ve İmzayı Doğrula
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			return c.String(http.StatusUnauthorized, "Geçersiz veya süresi dolmuş token.")
		}

		// 3. Başarılı: Claims verilerini sonraki handler'ların kullanması için Context'e kaydet
		c.Set("auth", true)
		c.Set("uid", claims.UserID)
		c.Set("name", claims.Name)
		c.Set("surname", claims.Surname)

		// 4. Sonraki Handler'a geç
		return next(c)
	}
}

func ProtectedPageHandler(c echo.Context) error {
    // Middleware'den kaydedilen kullanıcı verilerini çek
    auth := c.Get("auth")
    userID := c.Get("uid")
    userName := c.Get("name")
    surName := c.Get("surname")

    // Kullanıcıya özel içerik render et
    data := map[string]interface{}{
        "UserID": userID,
        "Name": userName,
        "surName": surName,
        "Auth":auth,
    }

    return c.Render(http.StatusOK, "index.html", data) 
}

// This endpoint initiates logout.
func spidLogout(c echo.Context) error {
    // If we don't have an open SPID session, do nothing.
    if spidSession == nil {
	return c.Redirect(http.StatusSeeOther, "/ssoweb")
    }

    // Craft the LogoutRequest.
    logoutreq, err := sp.NewLogoutRequest(spidSession)
    if err != nil {
 	return c.HTML(http.StatusBadRequest, err.Error())
    }

    // Save the ID of the LogoutRequest so that we can check it in the response
    // in order to prevent forgery.
    logoutReqID = logoutreq.ID

    return c.Redirect(http.StatusSeeOther, logoutreq.RedirectURL())
}

// This endpoint exposes a SingleLogoutService for our Service Provider, using
// a HTTP-POST or HTTP-Redirect binding (this package does not support SOAP).
// Identity Providers can direct both LogoutRequest and LogoutResponse messages
// to this endpoint.
func spidSLO(c echo.Context) error {
    if spidSession == nil {
	  return c.Redirect(http.StatusSeeOther, "/")
    }
    f_saml_response := c.FormValue("SAMLResponse")
    f_saml_request := c.FormValue("SAMLRequest")
    q_saml_response := c.QueryParam("SAMLResponse")
    q_saml_request := c.QueryParam("SAMLRequest")
    if (f_saml_response != "" || q_saml_response != "") && logoutReqID != "" {
	// This is the response to a SP-initiated logout.
	// Parse the response and catch validation errors.
	response, err := sp.ParseLogoutResponse(c.Request())
	if err != nil {
		fmt.Printf("Bad LogoutResponse received: %s\n", err)
  		return c.HTML(http.StatusBadRequest, err.Error())
	}

	// Validate the response, matching the ID of our request
	err = response.Validate(c.Request(), logoutReqID)
	if err != nil {
		fmt.Printf("Bad LogoutResponse received: %s\n", err)
  		return c.HTML(http.StatusBadRequest, err.Error())
	}

	// Logout was successful! Clear the local session.
	logoutReqID = ""
	spidSession = nil
	fmt.Println("Session successfully destroyed.")

	// TODO: handle partial logout. Log? Show message to user?
	// if (logoutres.Status() == logoutres.Partial) { ... }

	// Redirect user back to main page.
	c.Redirect(http.StatusSeeOther, "/")
    } else if (f_saml_request != "" || q_saml_request != "") {
	// This is a LogoutRequest (IdP-initiated logout).
	logoutreq, err := sp.ParseLogoutRequest(c.Request())
	if err != nil {
		fmt.Printf("Bad LogoutRequest received: %s\n", err)
  		return c.HTML(http.StatusBadRequest, err.Error())
	}

	// Now we should retrieve the local session corresponding to the SPID
	// session logoutreq.SessionIndex(). However, since we are implementing a HTTP-POST
	// binding, this HTTP request comes from the user agent so the current user
	// session is automatically the right one. This simplifies things a lot as
	// retrieving another session by SPID session ID is tricky without a more
	// complex architecture.
	status := spidsaml.SuccessLogout
	if logoutreq.SessionIndex() == spidSession.SessionIndex {
		spidSession = nil
	} else {
		status = spidsaml.PartialLogout
		fmt.Printf("SAML LogoutRequest session (%s) does not match current SPID session (%s)\n",
		logoutreq.SessionIndex(), spidSession.SessionIndex)
	}

	// Craft a LogoutResponse and send it back to the Identity Provider.
	logoutres, err := sp.NewLogoutResponse(logoutreq, status)
	if err != nil {
  		return c.HTML(http.StatusBadRequest, err.Error())
	}

	// Redirect user to the Identity Provider for logout.
	return c.Redirect(http.StatusSeeOther, logoutres.RedirectURL())
    } else {
	return c.HTML(http.StatusBadRequest, "Invalid Request")
    }
    return c.HTML(http.StatusBadRequest, "Invalid Request")

}
