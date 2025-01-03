package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/msteinert/pam"
)

const (
	agentInterface = "org.freedesktop.PolicyKit1.AuthenticationAgent"
	agentPath      = "/org/freedesktop/PolicyKit1/AuthenticationAgent"
	agentBusName   = "dev.benz.wpka.PolicyKit1.AuthenticationAgent"
)

type Agent struct {
	conn *dbus.Conn
}

// Subject represents a PolicyKit subject
type Subject struct {
	Kind    string
	Details map[string]dbus.Variant
}

func getPassword() (string, error) {
	return execute(), nil
}

// BeginAuthentication handles the authentication request
func (a *Agent) BeginAuthentication(actionId string, message string, iconName string, details map[string]string, cookie string, identities []interface{}) *dbus.Error {
	log.Printf("Authentication requested for action: %s\n", actionId)
	log.Printf("Message: %s\n", message)
	log.Printf("Cookie: %s\n", cookie)

	currentUser := os.Getenv("SUDO_USER")
	if currentUser == "" {
		currentUser = os.Getenv("USER")
	}
	if currentUser == "" {
		log.Printf("Could not determine user")
		return dbus.MakeFailedError(fmt.Errorf("could not determine user"))
	}

	log.Printf("Authenticating as user: %s", currentUser)

	userInfo, err := user.Lookup(currentUser)
	if err != nil {
		log.Printf("Failed to lookup user: %v", err)
		return dbus.MakeFailedError(err)
	}

	uid, err := strconv.ParseUint(userInfo.Uid, 10, 32)
	if err != nil {
		log.Printf("Failed to parse UID: %v", err)
		return dbus.MakeFailedError(err)
	}

	password, err := getPassword()
	if err != nil {
		log.Printf("Failed to get password: %v", err)
		return dbus.MakeFailedError(err)
	}

	err = PAMAuth("passwd", currentUser, password)
	if err != nil {
		log.Printf("Failed to authenticate with PAM: %v", err)
		return dbus.MakeFailedError(fmt.Errorf("invalid password"))
	}

	log.Printf("Password verified for user %s (uid: %d)", currentUser, uid)

	// Create the identity structure in the format PolicyKit expects: (sa{sv})
	identity := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{
		Kind: "unix-user",
		Details: map[string]dbus.Variant{
			"uid": dbus.MakeVariant(uint32(uid)),
		},
	}

	// Send authentication response
	obj := a.conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	call := obj.Call("org.freedesktop.PolicyKit1.Authority.AuthenticationAgentResponse2", 0,
		uint32(uid), // u
		cookie,      // s
		identity,    // (sa{sv})
	)

	if call.Err != nil {
		log.Printf("Failed to send authentication response: %v", call.Err)
		return dbus.MakeFailedError(call.Err)
	}

	log.Println("Authentication response sent successfully")
	return nil
}

func (a *Agent) CancelAuthentication(cookie string) *dbus.Error {
	log.Printf("Authentication cancelled for cookie: %s\n", cookie)
	return nil
}

func getCurrentSession() (string, error) {
	if session := os.Getenv("XDG_SESSION_ID"); session != "" {
		return session, nil
	}

	cmd := exec.Command("loginctl", "show-session", "self", "--property=Id")
	output, err := cmd.Output()
	if err == nil {
		session := strings.TrimPrefix(strings.TrimSpace(string(output)), "Id=")
		return session, nil
	}

	cmd = exec.Command("loginctl", "list-sessions", "--no-legend")
	output, err = cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get session: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 0 {
		fields := strings.Fields(lines[0])
		if len(fields) > 0 {
			return fields[0], nil
		}
	}

	return "", fmt.Errorf("no session found")
}

func main() {
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Fatalf("Failed to connect to system bus: %v", err)
	}

	reply, err := conn.RequestName(agentBusName,
		dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("Failed to request name: %v", err)
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatal("Name already taken")
	}

	agent := &Agent{conn: conn}
	err = conn.Export(agent, dbus.ObjectPath(agentPath), agentInterface)
	if err != nil {
		log.Fatalf("Failed to export agent: %v", err)
	}

	sessionId, err := getCurrentSession()
	if err != nil {
		log.Fatalf("Failed to get current session: %v", err)
	}
	log.Printf("Using session ID: %s", sessionId)

	// Create the subject structure exactly as PolicyKit expects
	subject := Subject{
		Kind: "unix-session",
		Details: map[string]dbus.Variant{
			"session-id": dbus.MakeVariant(sessionId),
		},
	}

	obj := conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	call := obj.Call("org.freedesktop.PolicyKit1.Authority.RegisterAuthenticationAgent", 0,
		subject,
		"en_US.UTF-8",
		agentPath,
	)

	if call.Err != nil {
		log.Fatalf("Failed to register authentication agent: %v", call.Err)
	}

	// Also register with options
	call = obj.Call("org.freedesktop.PolicyKit1.Authority.RegisterAuthenticationAgentWithOptions", 0,
		subject,
		"en_US.UTF-8",
		agentPath,
		map[string]dbus.Variant{},
	)

	if call.Err != nil {
		log.Printf("Warning: Failed to register with options: %v", call.Err)
	}

	log.Println("Successfully registered authentication agent")
	fmt.Println("PolicyKit agent started. Waiting for authentication requests...")

	select {}
}

func getCurrentUser() (*user.User, error) {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		return nil, fmt.Errorf("SUDO_USER environment variable not set")
	}
	return user.Lookup(sudoUser)
}

// getOriginalEnv gets the environment variables from the user's session
func getOriginalEnv(username string) ([]string, error) {
	cmd := exec.Command("ps", "e", "-u", username)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "WAYLAND_DISPLAY") {
			return strings.Fields(line), nil
		}
	}
	return nil, fmt.Errorf("no wayland session found")
}

func execute() string {
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run with sudo")
		os.Exit(1)
	}

	currentUser, err := getCurrentUser()
	if err != nil {
		fmt.Printf("Error getting current user: %v\n", err)
		os.Exit(1)
	}

	uid, err := strconv.ParseUint(currentUser.Uid, 10, 32)
	if err != nil {
		fmt.Printf("Error parsing UID: %v\n", err)
		os.Exit(1)
	}

	_, err = strconv.ParseUint(currentUser.Gid, 10, 32)
	if err != nil {
		fmt.Printf("Error parsing GID: %v\n", err)
		os.Exit(1)
	}

	// Get original environment variables
	origEnv, err := getOriginalEnv(currentUser.Username)
	if err != nil {
		fmt.Printf("Error getting original environment: %v\n", err)
		os.Exit(1)
	}

	// Parse environment variables
	envMap := make(map[string]string)
	for _, env := range origEnv {
		if strings.Contains(env, "=") {
			parts := strings.SplitN(env, "=", 2)
			envMap[parts[0]] = parts[1]
		}
	}

	args := os.Args[1:]

	cmd := exec.Command("sh", "-c", strings.Join(args, " "))

	// Build environment variables list
	var envList []string
	for k, v := range envMap {
		envList = append(envList, fmt.Sprintf("%s=%s", k, v))
	}

	// Add essential variables
	envList = append(envList,
		fmt.Sprintf("HOME=%s", currentUser.HomeDir),
		fmt.Sprintf("USER=%s", currentUser.Username),
		fmt.Sprintf("LOGNAME=%s", currentUser.Username),
		fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid),
		"XDG_SESSION_TYPE=wayland",
		"GDK_BACKEND=wayland",
	)

	cmd.Env = envList

	// // Set the user and group
	// cmd.SysProcAttr = &syscall.SysProcAttr{
	// 	Credential: &syscall.Credential{
	// 		Uid: uint32(uid),
	// 		Gid: uint32(gid),
	// 	},
	// }

	// Run the command
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		fmt.Printf("Error running command: %v\n", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	pw := ""

	for scanner.Scan() {
		pw = scanner.Text()
	}

	return pw
}

func PAMAuth(serviceName, userName, passwd string) error {
	t, err := pam.StartFunc(serviceName, userName, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return passwd, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("unrecognized PAM message style")
	})
	if err != nil {
		return err
	}

	if err = t.Authenticate(0); err != nil {
		return err
	}

	return nil
}
