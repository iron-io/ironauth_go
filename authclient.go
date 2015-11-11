// todo: make this open source

package authclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/iron-io/go/common"
	"gopkg.in/mgo.v2/bson"
)

func New(host string) *AuthClient {
	return &AuthClient{
		baseurl: host + "/1",
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				Dial: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).Dial,
				MaxIdleConnsPerHost: 512,
				TLSHandshakeTimeout: 10 * time.Second,
				TLSClientConfig: &tls.Config{
					ClientSessionCache: tls.NewLRUClientSessionCache(1024 * 8),
				},
			},
		},
	}
}

type AuthClient struct {
	baseurl string
	http    *http.Client
}

func (c *AuthClient) LoginUser(email, password string) (*common.User, error) {
	payload := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{email, password}
	result, err := c.makeRequest("POST", "/authentication", "", payload)
	if err != nil {
		return nil, err
	}
	return result.User, nil
}

func (c *AuthClient) CreateUser(token string, user *common.User) (*common.User, error) {
	u := struct { // password is is json:"-" need to override it
		*common.User
		Password string `json:"password,omitempty"`
	}{
		user, user.Password,
	}
	result, err := c.makeRequest("POST", "/users", token, u)
	if err != nil {
		return nil, err
	}
	return result.User, nil
}

func (c *AuthClient) GetUser(token, emailOrId string) (*common.User, error) {
	var payload BlankRequest
	result, err := c.makeRequest("GET", fmt.Sprintf("/users/%v", emailOrId), token, payload)
	if err != nil {
		return nil, err
	}
	return result.User, nil
}

func (c *AuthClient) GetUsers(adminToken, prev string, perPage int) ([]*common.User, error) {
	var payload BlankRequest
	url := "/users"
	if prev != "" {
		url += "?previous=" + prev
		if perPage > 0 {
			url += fmt.Sprintf("&per_page=%d", perPage)
		}
	} else if perPage > 0 {
		url += fmt.Sprintf("?per_page=%d", perPage)
	}
	result, err := c.makeRequest("GET", url, adminToken, payload)
	if err != nil {
		return nil, err
	}
	return result.Users, nil
}

func (c *AuthClient) UpdateUser(token, emailOrId string, user *common.User) (*common.User, error) {
	u := struct { // password is is json:"-" need to override it
		*common.User
		Password string `json:"password,omitempty"`
	}{
		user, user.Password,
	}
	result, err := c.makeRequest("PATCH", fmt.Sprintf("/users/%v", emailOrId), token, u)
	if err != nil {
		return nil, err
	}
	return result.User, nil
}

func (c *AuthClient) DeleteUser(token, email string) error {
	var payload BlankRequest
	_, err := c.makeRequest("DELETE", fmt.Sprintf("/users/%v", email), token, payload)
	return err
}

func (c *AuthClient) DeleteToken(token string) error {
	var payload BlankRequest
	_, err := c.makeRequest("DELETE", fmt.Sprintf("/tokens/%v", token), token, payload)
	return err
}

func (c *AuthClient) CreateToken(token string, t *common.Token) (*common.Token, error) {
	result, err := c.makeRequest("POST", "/tokens", token, t)
	if err != nil {
		return nil, err
	}
	return result.Token, nil
}

func (c *AuthClient) GetTokens(token, user_id string) ([]string, error) {
	var payload BlankRequest
	result, err := c.makeRequest("GET", fmt.Sprintf("/users/%v/tokens", user_id), token, payload)
	if err != nil {
		return nil, err
	}
	return result.Tokens, nil
}

func (c *AuthClient) GetToken(token string) (*common.Token, error) {
	var payload BlankRequest
	result, err := c.makeRequest("GET", fmt.Sprintf("/tokens/%v", token), token, payload)
	if err != nil {
		return nil, err
	}
	return result.Token, nil
}

func (c *AuthClient) GetProjects(token string) ([]*common.Project, error) {
	var payload BlankRequest
	result, err := c.makeRequest("GET", fmt.Sprintf("/projects"), token, payload)
	if err != nil {
		return nil, err
	}
	return result.Projects, nil
}

func (c *AuthClient) CreateProject(token string, p *common.Project) (*common.Project, error) {
	result, err := c.makeRequest("POST", "/projects", token, p)
	if err != nil {
		return nil, err
	}
	return result.Project, nil
}

func (c *AuthClient) GetProject(token, projectId string) (*common.Project, error) {
	var payload BlankRequest
	result, err := c.makeRequest("GET", fmt.Sprintf("/projects/%v", projectId), token, payload)
	if err != nil {
		return nil, err
	}
	return result.Project, nil
}

func (c *AuthClient) UpdateProject(token, projectId string, p *common.Project) (*common.Project, error) {
	result, err := c.makeRequest("PATCH", fmt.Sprintf("/projects/%v", projectId), token, p)
	if err != nil {
		return nil, err
	}
	return result.Project, nil
}

func (c *AuthClient) DeleteProject(token, projectId string) error {
	var payload BlankRequest
	_, err := c.makeRequest("DELETE", fmt.Sprintf("/projects/%v", projectId), token, payload)
	return err
}

func (c *AuthClient) ShareProject(token, projectId string, userIdsOrEmails []string, referrer string) error {
	payload := ShareRequest{EmailsOrIds: userIdsOrEmails, Referrer: referrer}
	_, err := c.makeRequest("PATCH", fmt.Sprintf("/projects/%v/share", projectId), token, payload)
	return err
}

func (c *AuthClient) UnshareProject(token, projectId string, userIdsOrEmails []string) error {
	payload := ShareRequest{EmailsOrIds: userIdsOrEmails}
	_, err := c.makeRequest("PATCH", fmt.Sprintf("/projects/%v/unshare", projectId), token, payload)
	return err
}

func (c *AuthClient) GetProjectShares(token, projectId string) ([]*common.User, error) {
	var payload BlankRequest
	result, err := c.makeRequest("GET", fmt.Sprintf("/projects/%v/share", projectId), token, payload)
	if err != nil {
		return nil, err
	}
	return result.Users, nil
}

func (c *AuthClient) Authenticate(token, projectId string) (admin bool, err error) {
	var payload BlankRequest
	authResp, err := c.makeRequest("GET", "/authentication?project_id="+projectId, token, payload)
	if err != nil {
		return false, err
	}
	return authResp.Admin, nil
}

func (c *AuthClient) makeRequest(action, path, token string, payload interface{}) (*AuthResponse, error) {
	url := c.baseurl + path

	p, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(action, url, bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	req.Header["Content-Type"] = []string{"application/json"}
	req.Header["Authorization"] = []string{fmt.Sprintf("OAuth %v", token)}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(ioutil.Discard, resp.Body) // gotta flush it
		resp.Body.Close()
	}()
	var result AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, &ApiError{Code: resp.StatusCode, Msg: result.Msg}
	}
	return &result, nil
}

type BlankRequest struct{}

type ShareRequest struct {
	EmailsOrIds []string `json:"emails"`
	Referrer    string   `json:"referrer,omitempty"`
}

// this is kinda dumb
type AuthResponse struct {
	Admin    bool              `json:"admin"`
	Msg      string            `json:"msg"`
	User     *common.User      `json:"user"`
	Users    []*common.User    `json:"users"`
	Token    *common.Token     `json:"token"`
	Project  *common.Project   `json:"project"`
	Tokens   []string          `json:"tokens"`
	Projects []*common.Project `json:"projects"`
}

type ApiError struct {
	Code int
	Msg  string `json:"msg"`
}

func (e *ApiError) Error() string   { return e.Msg }
func (e *ApiError) StatusCode() int { return e.Code }

type Flags map[string]bool

type Project struct {
	Id                    bson.ObjectId   `json:"id,omitempty"`
	UserId                bson.ObjectId   `json:"user_id,omitempty"`
	Name                  string          `json:"name,omitempty"`
	Type                  string          `json:"type,omitempty"`
	Partner               string          `json:"partner,omitempty"`
	Status                string          `json:"status,omitempty"`
	MaxSchedules          int32           `json:"max_schedules,omitempty"`
	Flags                 Flags           `json:"flags,omitempty"`
	SharedWith            []bson.ObjectId `json:"shared_with,omitempty"`
	NotificationsDisabled bool            `json:"notifications_disabled,omitempty"`
	NotificationsEmail    string          `json:"notifications_email,omitempty"`
	SyslogUrl             string          `json:"syslog_url,omitempty"`
}

type Token struct {
	Id     bson.ObjectId `json:"_id"`
	UserId bson.ObjectId `json:"user_id"`
	Name   string        `json:"name"`
	Token  string        `json:"token"`
	Admin  bool          `json:"admin,omitempty"`

	Claims map[string]interface{} `json:"claims,omitempty"`
}

type Partner struct {
	Name    string `json:"name"`    // e.g. "heroku"
	Product string `json:"product"` // e.g. "iron_mq"
}

type PlanWorkerEntry struct {
	ConcurrentWorkers int      `json:"concurrent_workers,omitempty"`
	MaxTimeout        int      `json:"max_timeout,omitempty"`
	MaxPayloadSize    int      `json:"max_payload_size,omitempty"`
	Free              bool     `json:"free"`
	KeepTaskPriority  bool     `json:"keep_task_priority,omitempty"`
	Clusters          []string `json:"clusters,omitempty"`
	MaxScheduledJobs  int      `json:"scheduled_jobs,omitempty"`
	CustomImages      bool     `json:"custom_images,omitempty"`
	MaxImageSize      int64    `json:"max_image_size,omitempty"`
	CustomClusters    bool     `json:"custom_clusters,omitempty"`
}

type PlanMQEntry struct {
	MessageSize int      `json:"message_size,omitempty"`
	Clusters    []string `json:"clusters,omitempty"` // list of unique tags
}

type User struct {
	Id                bson.ObjectId   `json:"user_id"`
	Name              string          `json:"name"`
	Email             string          `json:"email"`
	Tokens            []string        `json:"tokens"`
	Status            string          `json:"status,omitempty"`
	PlanWorker        PlanWorkerEntry `json:"plan_worker"`
	PlanMQ            PlanMQEntry     `json:"plan_mq"`
	DockerCredentials []string        `json:"docker_credentials,omitempty"`
	Flags             Flags           `json:"flags,omitempty"`
	Partner           *Partner        `json:"partner,omitempty"`
	ApiTokenId        bson.ObjectId   `json:"api_token_id,omitempty"`
}
