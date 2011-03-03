// Copyright 2010 Gary Burd
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/garyburd/twister/oauth"
	"github.com/garyburd/twister/server"
	"github.com/garyburd/twister/web"
	"http"
	"io/ioutil"
	"json"
	"log"
	"os"
	"strings"
	"template"
)

var oauthClient = oauth.Client{
	Credentials:                   oauth.Credentials{clientToken, clientSecret},
	TemporaryCredentialRequestURI: "https://www.google.com/accounts/OAuthGetRequestToken",
	ResourceOwnerAuthorizationURI: "https://www.google.com/accounts/OAuthAuthorizeToken",
	TokenRequestURI:               "https://www.google.com/accounts/OAuthGetAccessToken",
	Scope:			       "https://orkut.gmodules.com/social/rest",
}

// encodeCredentials encodes OAuth credentials in a format suitable for storing in a cookie.
func encodeCredentials(c *oauth.Credentials) string {
	return http.URLEscape(c.Token) + "/" + http.URLEscape(c.Secret)
}

// credentials returns oauth credentials stored in cookie with name key.
func credentials(req *web.Request, key string) (*oauth.Credentials, os.Error) {
	s, found := req.Cookie.Get(key)
	if !found {
		return nil, os.NewError("main: missing cookie")
	}
	a := strings.Split(s, "/", -1)
	if len(a) != 2 {
		return nil, os.NewError("main: bad credential cookie")
	}
	token, err := http.URLUnescape(a[0])
	if err != nil {
		return nil, os.NewError("main: bad credential cookie")
	}
	secret, err := http.URLUnescape(a[1])
	if err != nil {
		return nil, os.NewError("main: bad credential cookie")
	}
	return &oauth.Credentials{token, secret}, nil
}

// login redirects the user to the Twitter authorization page.
func login(req *web.Request) {
	callback := req.URL.Scheme + "://" + req.URL.Host + "/twitter-callback"
	temporaryCredentials, err := oauthClient.RequestTemporaryCredentials(callback)
	if err != nil {
		req.Error(web.StatusInternalServerError, err)
		return
	}
	req.Redirect(oauthClient.AuthorizationURL(temporaryCredentials), false,
		web.HeaderSetCookie, fmt.Sprintf("tmp=%s; Path=/; HttpOnly", encodeCredentials(temporaryCredentials)))
}

// twitterCallback handles OAuth callbacks from Twitter.
func twitterCallback(req *web.Request) {
	temporaryCredentials, err := credentials(req, "tmp")
	if err != nil {
		req.Error(web.StatusNotFound, err)
		return
	}
	s, found := req.Param.Get("oauth_token")
	if !found {
		req.Error(web.StatusNotFound, os.NewError("main: no token"))
		return
	}
	if s != temporaryCredentials.Token {
		req.Error(web.StatusNotFound, os.NewError("main: token mismatch"))
		return
	}
	tokenCredentials, _, err := oauthClient.RequestToken(temporaryCredentials, req.Param.GetDef("oauth_verifier", ""))
	if err != nil {
		req.Error(web.StatusNotFound, err)
		return
	}
	req.Redirect("/", false,
		web.HeaderSetCookie, fmt.Sprintf("tok=%s; Path=/; HttpOnly; Expires=%s",
			encodeCredentials(tokenCredentials),
			web.FormatDeltaDays(30)))
}

// homeLoggedOut handles request to the home page for logged out users.
func homeLoggedOut(req *web.Request) {
	homeLoggedOutTempl.Execute(req,
		req.Respond(web.StatusOK, web.HeaderContentType, web.ContentTypeHTML))
}

// home handles requests to the home page.
func home(req *web.Request) {
	fmt.Print(req)
	token, err := credentials(req, "tok")
	if err != nil {
		homeLoggedOut(req)
		return
	}
	param := make(web.StringsMap)
	url := "http://www.orkut.com/social/rest/people/@me/@friends"
	oauthClient.SignParam(token, "GET", url, param)
	url = url + "?" + string(param.FormEncode())
	resp, _, err := http.Get(url)
	if err != nil {
		req.Error(web.StatusInternalServerError, err)
		return
	}
	p, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		req.Error(web.StatusInternalServerError, err)
		return
	}
	if resp.StatusCode != 200 {
		req.Error(web.StatusInternalServerError, os.NewError(fmt.Sprint("Status ", resp.StatusCode)))
		return
	}
	w := req.Respond(web.StatusOK, web.HeaderContentType, "text/plain")
	var buf bytes.Buffer
	json.Indent(&buf, p, "", "  ")
	log.Print("START")
	w.Write(buf.Bytes())
	log.Print("END")
}

func main() {
	flag.Parse()
	h := web.ProcessForm(10000, true, web.DebugLogger(true, web.NewRouter().
		Register("/", "GET", home).
		Register("/login", "GET", login).
		Register("/account/twitter-callback", "GET", twitterCallback).
		Register("/twitter-callback", "GET", twitterCallback)))

	err := server.ListenAndServe("localhost:8080", ":8080", h)
	if err != nil {
		log.Exit("ListenAndServe:", err)
	}
}

var homeLoggedOutTempl = template.MustParse(homeLoggedOutStr, nil)

const homeLoggedOutStr = `
<html>
<head>
</head>
<body>
<a href="/login"><img src="http://a0.twimg.com/images/dev/buttons/sign-in-with-twitter-d.png"></a>
</body>
</html>`

var homeTempl = template.MustParse(homeStr, nil)

const homeStr = `
<html>
<head>
</head>
<body>
<ul>
<li><a href="/core">Core functionality</a>
<li><a href="/chat">Chat using WebSockets</a>
</ul>
</body>
</html>`
