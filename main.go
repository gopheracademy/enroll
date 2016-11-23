package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"github.com/gorilla/mux"
	"github.com/kr/pretty"
	"github.com/pkg/errors"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	sshkey "github.com/yosida95/golang-sshkey"
	"golang.org/x/oauth2"
)

// Manifest is a struct that represents the variables in a class
type Manifest struct {
	Nodes     int
	Zip       string
	Name      string
	ShortName string
}

var courses = map[string]Manifest{
	"distributed": Manifest{Nodes: 3, Zip: "distributed", Name: "Go + Distributed Computing", ShortName: "distributed"},
}

/*var courses = map[string]Manifest{
	"gobeyond":   Manifest{Nodes: 1, Zip: "gobeyond", Name: "Go: Beyond the Basics", ShortName: "gobeyond"},
	"distributed":       Manifest{Nodes: 3, Zip: "distributed", Name: "Go + Distributed Computing", ShortName: "distributed"},
	"kubernetes": Manifest{Nodes: 3, Zip: "kubernetes", Name: "Kubernetes: From Zero To Production", ShortName: "kubernetes"},
}
*/

func main() {

	server := NewServer()

	http.Handle("/", server.Router)

	log.Println("Starting HTTP server on 8080 ...")
	log.Fatal(http.ListenAndServe(":8080", nil))

}

var baseImageID = 20340323
var pat = os.Getenv("PAT")
var sat = os.Getenv("SAT")
var mcapi = os.Getenv("MCAPI")

// TokenSource is for Digital Ocean
type TokenSource struct {
	AccessToken string
}

// Token returns an access token for DO
func (t *TokenSource) Token() (*oauth2.Token, error) {
	token := &oauth2.Token{
		AccessToken: t.AccessToken,
	}
	return token, nil
}

func createPublicKey(client *godo.Client, name, key string) (int, error) {

	pubkey, err := sshkey.UnmarshalPublicKey(key)
	if err != nil {
		fmt.Println("error unmarshaling public key")
	}
	nativePub := pubkey.Public().(*rsa.PublicKey)

	fmt.Println(pubkey.Type())
	fmt.Println(pubkey.Type() == sshkey.KEY_RSA)
	fmt.Println(nativePub.E)
	fmt.Println(pubkey.Length())
	fmt.Println(pubkey.Comment())
	fmt.Println(sshkey.PrettyFingerprint(pubkey, crypto.MD5))

	createRequest := &godo.KeyCreateRequest{
		Name:      name + "-gophertrain",
		PublicKey: key,
	}

	newkey, _, err := client.Keys.Create(createRequest)
	if err != nil {
		fmt.Println("existing key")
		fp, e := sshkey.PrettyFingerprint(pubkey, crypto.MD5)
		if e != nil {
			return 0, errors.Wrap(e, "getting key fingerprint")
		}

		fmt.Println("looking up existing key")
		ekey, _, e := client.Keys.GetByFingerprint(fp)
		if e != nil {
			fmt.Println("failed looking up existing key")
			return 0, errors.Wrap(e, "retrieving existing key")
		}
		return ekey.ID, nil

	}

	return newkey.ID, nil
}

func createAndNotify(man Manifest, email, username, password, sshkey string) {

	drops, err := createDropletCluster(man, email, username, password, sshkey)
	if err != nil {
		log.Println("error creating droplets:", err)
	}
	pretty.Println(drops)

	post := `{"email_address": "EMAIL","status": "subscribed"}`
	post = strings.Replace(post, "EMAIL", email, -1)

	mcurl := "https://us1.api.mailchimp.com/3.0/lists/dccb0487a6/members"

	req, err := http.NewRequest("POST", mcurl, bytes.NewBuffer([]byte(post)))
	req.Header.Set("Authorization", "apikey "+mcapi)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("MC Error: ", err)
	}

	fmt.Println("MC response Status:", resp.Status)
	fmt.Println("MC response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("MC response Body:", string(body))

	// email finished thing

	from := mail.NewEmail("Brian Ketelsen", "me@brianketelsen.com")
	to := mail.NewEmail(username, email)

	nodenames := nodeNames(man, username)

	subject := "Your server(s) are ready to use for your class!"

	message := "Congratulations, your virtual student classroom servers are ready to use. \nIf prompted for a username and password, use the username/password combination you \ncreated when you enrolled at https://gophertrain.com. \n\n\n"

	for _, node := range nodenames {

		message = message + "Node: " + node + ".gophertrain.com:\n"
		ssh := fmt.Sprintf("ssh %s@%s.gophertrain.com", username, node)
		ide := fmt.Sprintf("https://%s.gophertrain.com/ide/", node)
		shell := fmt.Sprintf("https://%s.gophertrain.com/shell/", node)
		message = message + "SSH Access: \n "
		message = message + ssh + "\n"
		message = message + "Web Shell: \n "
		message = message + shell + "\n"
		message = message + "Web IDE - ONLY available after your first login: \n "
		message = message + ide + "\n\n"
	}

	message = message + "\n\n Using these servers is governed under the terms and conditions of your course. \nThe servers will be decomissioned at the end of your class, and are solely \nfor your private use during the duration of the course.\n\n Thanks!\n\n Brian Ketelsen "
	time.Sleep(45 * time.Second)
	content := mail.NewContent("text/plain", message)
	m := mail.NewV3MailInit(from, subject, to, content)

	request := sendgrid.GetRequest(sat, "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	request.Body = mail.GetRequestBody(m)
	response, err := sendgrid.API(request)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
	}

}

func nodeNames(m Manifest, username string) []string {
	nodenames := make([]string, m.Nodes)
	for i := 0; i < m.Nodes; i++ {
		nodenames[i] = username + "-node" + strconv.Itoa(i+1)

	}
	return nodenames
}

func createDropletCluster(m Manifest, email, username, password, sshkey string) ([]*godo.Droplet, error) {
	tokenSource := &TokenSource{
		AccessToken: pat,
	}

	oauthClient := oauth2.NewClient(oauth2.NoContext, tokenSource)
	client := godo.NewClient(oauthClient)

	var keys []godo.DropletCreateSSHKey
	keyID, err := createPublicKey(client, username, sshkey)
	if err != nil {
		keys = []godo.DropletCreateSSHKey{}
	} else {
		keys = []godo.DropletCreateSSHKey{godo.DropletCreateSSHKey{ID: keyID}}
	}

	nodenames := nodeNames(m, username)
	createRequest := &godo.DropletMultiCreateRequest{
		Names:    nodenames,
		Region:   "sfo1",
		Size:     "2gb",
		UserData: createUser(username, password) + startData + createUnit(m, username, username, password, email),
		SSHKeys:  keys,
		Image: godo.DropletCreateImage{
			ID: baseImageID,
		},
		IPv6: true,
	}
	droplets, _, err := client.Droplets.CreateMultiple(createRequest)
	fmt.Println("droplet:", droplets, err)
	if err != nil {
		return nil, errors.Wrap(err, "Creating New Droplet")
	}
	fmt.Println("waiting for creation")
	time.Sleep(20 * time.Second)
	finalDrops := make([]*godo.Droplet, 3)
	for x, dropl := range droplets {
		var drop *godo.Droplet
		for {
			var err error
			drop, _, err = client.Droplets.Get(dropl.ID)
			if err != nil {
				if err != nil {
					return nil, errors.Wrap(err, "Waiting For New Droplet")
				}
			}
			if drop.Status == "active" {
				fmt.Println("status", drop.Status)
				break
			}
			fmt.Println("not active", drop.Status)
			time.Sleep(10 * time.Second)
		}

		ip, err := drop.PublicIPv4()
		if err != nil {
			return nil, errors.Wrap(err, "Getting Droplet Public IP")
		}
		fmt.Println(drop.Name, ip, err)

		dnsCreateRequest := &godo.DomainRecordEditRequest{
			Type: "A",
			Name: drop.Name,
			Data: ip,
		}

		domainRecord, _, err := client.Domains.CreateRecord("gophertrain.com", dnsCreateRequest)

		if err != nil {
			return nil, errors.Wrap(err, "Creating DNS Record for new Droplet")
		}
		fmt.Println(domainRecord, err)
		finalDrops[x] = drop
	}
	return finalDrops, err

}

const startData = `
apt-get install -y shellinabox unzip
curl -L getcaddy.com | bash
mkdir -p /opt/caddy

cat <<EOF > /etc/systemd/system/caddy.service
[Unit]
Description=Caddy webserver
Documentation=https://caddyserver.com/
After=network.target

[Service]
WorkingDirectory=/opt/caddy
LimitNOFILE=16384
PIDFile=/var/run/caddy/caddy.pid
ExecStart=/usr/local/bin/caddy -agree -email bketelsen@gmail.com -pidfile=/var/run/caddy/caddy.pid
Restart=on-failure
StartLimitInterval=600

[Install]
WantedBy=multi-user.target
EOF
systemctl disable kubelet
systemctl stop kubelet
export PATH=/usr/local/go/bin:$PATH
export GOPATH=/root/go
go get github.com/bketelsen/wide
go get github.com/bketelsen/wide/cmd/wuser
cp /root/go/bin/wide /usr/local/bin/wide
cp /root/go/bin/wuser /usr/local/bin/wuser
cp -R /root/go/src/github.com/bketelsen/wide /opt/
`

func createUnit(m Manifest, host, username, password, email string) string {
	unit := `hostname=$(hostname); cat <<EOF > /opt/caddy/Caddyfile
$hostname.gophertrain.com/shell {
	proxy / https://127.0.0.1:4200 {
		insecure_skip_verify
		websocket
	}
}

$hostname.gophertrain.com/static {
        root /opt/wide/static
}

$hostname.gophertrain.com/ide {
        proxy / http://127.0.0.1:7070/ide {
                websocket
        }
}
EOF
systemctl daemon-reload
systemctl enable caddy
systemctl start caddy
cat <<EOF >> /home/USERNAME/.bashrc
export PATH=$HOME/go/bin:/usr/local/go/bin:$PATH
export GOPATH=/home/USERNAME/go
go get -u github.com/nsf/gocode
go get -u github.com/visualfc/gotools
systemctl --user import-environment
systemctl --user enable wide
systemctl --user start wide
file=/home/USERNAME/DOWNLOAD.zip
if [ ! -e "$file" ]; then
	cd && wget https://gophers:rule@files.brianketelsen.com/DOWNLOAD.zip && unzip DOWNLOAD.zip && cp -R DOWNLOAD/src go/
fi
EOF
mkdir /home/USERNAME/go
chown -R USERNAME:USERNAME /home/USERNAME/go
mkdir /home/USERNAME/playground
chown -R USERNAME:USERNAME /home/USERNAME/playground
chown USERNAME:USERNAME /home/USERNAME/.bashrc
chown -R USERNAME:USERNAME /opt/wide
cd /opt/wide
wuser -e EMAIL -h /home/USERNAME/go -p 'PASSWORD' -u USERNAME
chown -R USERNAME:USERNAME /opt/wide/conf/users/USERNAME.json
cp /usr/local/bin/wide /opt/wide/wide
mkdir -p /home/USERNAME/.config/systemd/user
chown -R USERNAME:USERNAME /home/USERNAME/.config
cat <<EOF > /home/USERNAME/.config/systemd/user/wide.service
[Unit]
Description=WIDE IDE

[Service]
WorkingDirectory=/opt/wide
ExecStart=/opt/wide/wide --channel wss://$hostname.gophertrain.com/ide --conf /opt/wide/conf/wide.json --ip 0.0.0.0 --context /ide

[Install]
WantedBy=default.target
EOF

`
	unit = strings.Replace(unit, "DOWNLOAD", m.Zip, -1)
	unit = strings.Replace(unit, "USERNAME", username, -1)
	unit = strings.Replace(unit, "EMAIL", email, -1)
	return strings.Replace(unit, "PASSWORD", password, -1)
}

func createUser(username, password string) string {
	var createScript []byte

	createScript = append(createScript, []byte("#!/bin/bash")...)
	createScript = append(createScript, '\n')
	createScript = append(createScript, []byte("PASSWORD=")...)
	createScript = append(createScript, []byte("`perl -e 'printf(")...)
	createScript = append(createScript, '"')
	createScript = append(createScript, []byte("%s")...)
	createScript = append(createScript, '\\')

	createScript = append(createScript, 'n')
	createScript = append(createScript, '"')

	createScript = append(createScript, []byte(", crypt($ARGV[0],")...)
	createScript = append(createScript, '"')
	createScript = append(createScript, []byte("password")...)
	createScript = append(createScript, '"')
	createScript = append(createScript, ')')
	createScript = append(createScript, ')')
	createScript = append(createScript, '\'')
	createScript = append(createScript, ' ')
	createScript = append(createScript, '"')
	createScript = append(createScript, []byte(password)...)
	createScript = append(createScript, '"')
	createScript = append(createScript, '`')
	createScript = append(createScript, '\n')

	createScript = append(createScript, []byte("sudo useradd -G docker,sudo -m -s /bin/bash -p $PASSWORD ")...)
	createScript = append(createScript, []byte(username)...)
	createScript = append(createScript, '\n')

	createScript = append(createScript, []byte("cp -R /root/.ssh /home/")...)
	createScript = append(createScript, []byte(username)...)
	createScript = append(createScript, '/')
	createScript = append(createScript, '\n')
	createScript = append(createScript, []byte("chown -R ")...)

	createScript = append(createScript, []byte(username)...)
	createScript = append(createScript, ':')
	createScript = append(createScript, []byte(username)...)
	createScript = append(createScript, []byte(" /home/")...)

	createScript = append(createScript, []byte(username)...)

	createScript = append(createScript, '/')
	createScript = append(createScript, []byte(".ssh")...)

	createScript = append(createScript, '\n')

	return string(createScript)
}

func numberPrefix(username string) bool {

	if strings.HasPrefix("1", username) {
		return true
	}
	if strings.HasPrefix("2", username) {
		return true
	}
	if strings.HasPrefix("3", username) {
		return true
	}
	if strings.HasPrefix("4", username) {
		return true
	}
	if strings.HasPrefix("5", username) {
		return true
	}
	if strings.HasPrefix("6", username) {
		return true
	}
	if strings.HasPrefix("7", username) {
		return true
	}
	if strings.HasPrefix("8", username) {
		return true
	}
	if strings.HasPrefix("9", username) {
		return true
	}
	if strings.HasPrefix("0", username) {
		return true
	}

	return false
}

// SignupResponse is the output to the template after posted
// no longer used this way - refactor!
type SignupResponse struct {
	Error        bool
	ErrorMessage string
	Username     string
	Droplets     []*godo.Droplet
	Courses      map[string]Manifest
}

// Server is the struct that serves the web app
type Server struct {
	Router *mux.Router
}

// NewServer returns a new server
func NewServer() *Server {
	s := &Server{}
	router := mux.NewRouter()
	s.Router = router

	router.HandleFunc("/enroll", s.ServeEnroll).Methods("GET")
	router.HandleFunc("/enroll", s.Enroll).Methods("POST")

	return s
}

// ServeEnroll serves the get verb
func (s *Server) ServeEnroll(w http.ResponseWriter, req *http.Request) {
	t, err := template.New("body").Parse(form)
	if err != nil {
		log.Print("template parsing error: ", err)
	}

	wr := &SignupResponse{Courses: courses}
	err = t.Execute(w, wr)
	if err != nil {
		log.Print("template executing error: ", err)
	}
}

// Enroll serves the POST
func (s *Server) Enroll(w http.ResponseWriter, req *http.Request) {

	t, err := template.New("body").Parse(form)
	if err != nil {
		log.Print("template parsing error: ", err)
	}

	wr := &SignupResponse{Courses: courses}

	courseid := req.PostFormValue("coursetoken")
	if courseid == "" {
		w.WriteHeader(400)
		e := t.Execute(w, &SignupResponse{Error: true, ErrorMessage: "Course Token Required"})
		if e != nil {
			log.Print("template executing error: ", err)
		}
		return
	}

	manifest, ok := courses[courseid]
	if !ok {
		w.WriteHeader(400)
		e := t.Execute(w, &SignupResponse{Error: true, ErrorMessage: "Unknown Course", Courses: courses})
		if e != nil {
			log.Print("template executing error: ", err)
		}
		return
	}

	fmt.Println(manifest.ShortName)

	username := req.PostFormValue("username")
	email := req.PostFormValue("email")
	password := req.PostFormValue("password")
	password2 := req.PostFormValue("password2")

	if numberPrefix(username) {
		w.WriteHeader(400)
		e := t.Execute(w, &SignupResponse{Error: true, ErrorMessage: "Username May Not start with a number"})
		if e != nil {
			log.Print("template executing error: ", e)
		}
		return
	}
	if password != password2 {
		w.WriteHeader(400)
		e := t.Execute(w, &SignupResponse{Error: true, ErrorMessage: "Passwords don't match"})
		if e != nil {
			log.Print("template executing error: ", e)
		}
		return
	}

	//name := req.PostFormValue("name")
	//email := req.PostFormValue("email")

	sshkey := req.PostFormValue("sshkey")

	if sshkey == "" {
		w.WriteHeader(400)
		e := t.Execute(w, &SignupResponse{Error: true, ErrorMessage: "SSH Key Required!"})
		if e != nil {
			log.Print("template executing error: ", e)
		}
		return
	}

	go createAndNotify(manifest, email, username, password, sshkey)

	w.WriteHeader(201)
	wr.Username = username
	e := t.Execute(w, wr)
	if e != nil {
		log.Print("template executing error: ", err)
	}

}

const form = `<!DOCTYPE html>
<html>
<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/font-awesome/4.3.0/css/font-awesome.min.css">
<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<link href='https://fonts.googleapis.com/css?family=Varela+Round' rel='stylesheet' type='text/css'>
<script   src="https://code.jquery.com/jquery-3.1.1.min.js"   integrity="sha256-hVVnYaiADRTO2PzUGmuLJr8BLUSjGIZsDYGmIJLv2b8="   crossorigin="anonymous"></script>
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
<body>

<div class="container">
{{ if .Error }}
<div class="alert alert-danger">
<strong>Error:<strong> {{.ErrorMessage}}
</div>
{{ end  }}
{{ if .Username}}
<div class="alert alert-success">
<strong>{{.Username}}<strong>  was created<br/> {{$u := .Username}}
<strong>Check Your Email</strong> for login instructions<br/>
</div>
{{ end  }}
<div class="alert alert-success">
				<h3>Welcome to Brian Ketelsen's Training. <br/>This form will create servers for your use during your training.  The servers will be provisioned with the course materials and tools you need to complete the exercises in class.<br/> After you submit the form you will receive an email with instructions on how to log in to your server(s).</h3>
				</div>
        <div class="row centered-form">
        <div class="col-xs-12 col-sm-8 col-md-4 col-sm-offset-2 col-md-offset-4">
        	<div class="panel panel-default">
        		<div class="panel-heading">
				<h3 class="panel-title">Enter Credentials for your new Server:</h3>
			 			</div>
			 			<div class="panel-body">
			    		<form id="createform" role="form" action="/enroll" method="POST" onsubmit="return checkForm(this);">
			    					<div class="form-group">
										<input type="text" name="username" id="username" class="form-control input-sm" placeholder="Enter a Username">
			    					</div>
			    					<div class="form-group">
			    						<input type="text" name="name" id="name" class="form-control input-sm" placeholder="Full Name">
			    					</div>

			    			<div class="form-group">
			    				<input type="email" name="email" id="email" class="form-control input-sm" placeholder="Email Address">
			    			</div>

			    					<div class="form-group">
			    						<input type="password" name="password" id="password" class="form-control input-sm" placeholder="Enter a Password">
			    					</div>

			    					<div class="form-group">
			    						<input type="password" name="password2" id="password2" class="form-control input-sm" placeholder="Repeat Password">
			    					</div>
			    			<div class="form-group">
								<select name="coursetoken">
								{{ range $i, $course:= .Courses }}
									<option value="{{$course.ShortName}}">{{$course.Name}}</option>
									{{ end }}
								</select>
			    			</div>
			    			
			    			<div class="form-group">
			    				<input type="textbox" name="sshkey" id="sshkey" class="form-control input-sm" placeholder="SSH Public Key">
			    			</div>
			    			<input type="submit" name="register" value="Register" class="btn btn-info btn-block">
			    		
			    		</form>
			    	</div>
	    		</div>
    		</div>
    	</div>
    </div>
	<script type="text/javascript">
  function checkForm(form) // Submit button clicked
  {

    form.register.disabled = true;
    form.register.value = "Working--Please wait...";
    return true;
  }
	</script>
</body>
</html>`
