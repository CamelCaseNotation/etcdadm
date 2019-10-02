/*
Copyright 2019 The etcdadm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

--
*/

package auth

import (
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"time"

	"sigs.k8s.io/etcdadm/apis"
	"sigs.k8s.io/etcdadm/certs"
	"sigs.k8s.io/etcdadm/util"
)

// CreateTenant uses etcdctl to create a user "name" according to official etcd documentation, and then assigns it a role with readwrite access to the prefix "/name"
// specified prefix
// https://github.com/etcd-io/etcd/blob/master/Documentation/op-guide/authentication.md
func CreateTenant(cfg *apis.EtcdAdmConfig, name string) error {
	if err := createUserAndRole(cfg, name); err != nil {
		return err
	}
	if err := certs.CreateTenantClientCertAndKeyFiles(cfg, name); err != nil {
		return err
	}
	return nil
}

// EnableAuthWithRootUser will use etcdctl to create the root user with a randomly generated password and enable auth for etcd.
// This should be invoked during etcdadm init, perhaps gated behind a boolean flag like '--enable-auth' (true by default)
func EnableAuthWithRootUser(cfg *apis.EtcdAdmConfig) error {
	if err := createRootUser(cfg); err != nil {
		return err
	}
	if err := authEnable(cfg); err != nil {
		return err
	}
	return nil
}

// SetupRootUserConfig sets the generated password for root user in EtcdAdmnConfig struct such that it can later be
// written to the etcdctl env file
func SetupRootUserConfig(cfg *apis.EtcdAdmConfig) error {
	cfg.EtcdctlRootUserPassword = randomPassword()
	return nil
}

func authEnable(cfg *apis.EtcdAdmConfig) error {
	etcdctl, err := ensureEtcdctlPath(cfg)
	if err != nil {
		return err
	}
	cmdArgs := []string{
		"auth",
		"enable",
	}
	cmd := exec.Command(etcdctl, cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("[auth] `%v` command failed with error: %v", cmd.Args, err)
	}
	fmt.Printf("[auth] %s", out)
	return nil
}

// createUserAndRole is functionally equivalent to the following commands:
// `etcdctl user add <name>`
// `etcdctl role add <name>`
// `etcdctl role grant-permission <name> --prefix=true readwrite /<name>/`
// `etcdctl user grant-role <name> <name>`
func createUserAndRole(cfg *apis.EtcdAdmConfig, name string) error {
	etcdctl, err := ensureEtcdctlPath(cfg)
	if err != nil {
		return err
	}

	// FIXME: surely there's a better way to validate this?
	if strings.Contains(name, "/") {
		return fmt.Errorf("[auth] invalid value for --name: '%s' cannot contain / (try using a DNS-compliant value)", name)
	}

	// os.Setenv("ETCDCTL_USER", fmt.Sprintf("root:%s", cfg.EtcdctlRootUserPassword))

	cmds := []*exec.Cmd{
		// Create user
		exec.Command(etcdctl, []string{
			"user",
			"add",
			fmt.Sprintf("%s:%s", name, randomPassword()),
		}...),
		// Create role
		exec.Command(etcdctl, []string{
			"role",
			"add",
			name,
		}...),
		// Define permissions for role
		exec.Command(etcdctl, []string{
			"role",
			"grant-permission",
			name, // role name
			"--prefix=true",
			"readwrite",
			fmt.Sprintf("/%s/", name),
		}...),
		// Assign role to user
		exec.Command(etcdctl, []string{
			"user",
			"grant-role",
			name, // role name
			name,
		}...),
	}

	for _, cmd := range cmds {
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("[auth] `%v` command failed with error: %v", cmd.Args, err)
		}
		fmt.Printf("[auth] %s", out)
	}
	return nil
	// Doing above until I decide granular handling of errors if a user/role already exists when trying to create them is worth it
	// Add role
	// cmdArgs := []string{
	// 	"role",
	// 	"add",
	// 	name,
	// }
	// cmd := exec.Command(etcdctlWrapper, cmdArgs...)
	// out, err := cmd.Output()
	// if err != nil {
	// 	// TODO: handle already existing roles by checking err output for `Error: etcdserver: role name already exists`
	// 	return fmt.Errorf("[auth] `%v` command failed with error: %v", cmd.Args, err)
	// }

	// // Assign role to user of same name with full permissions to prefix of same name
	// cmdArgs = []string{
	// 	"role",
	// 	"grant-permission",
	// 	name, // role name
	// 	"--prefix=true",
	// 	"readwrite",
	// 	fmt.Sprintf("/%s/", name),
	// }
	// cmd = exec.Command(etcdctlWrapper, cmdArgs...)
	// out, err = cmd.Output()
	// if err != nil {
	// 	// TODO: handle error if role name (arg after "grant-permission") does not exist. Error will be `Error: etcdserver: role name not found`
	// 	return fmt.Errorf("[auth] `%v` command failed with error: %v", cmd.Args, err)
	// }
	// return nil
}

// createRootUser uses etcdctl to create users according to official etcd documentation
// https://github.com/etcd-io/etcd/blob/master/Documentation/op-guide/authentication.md
func createRootUser(cfg *apis.EtcdAdmConfig) error {
	etcdctl, err := ensureEtcdctlPath(cfg)
	if err != nil {
		return err
	}
	// Generate a password for non-root users. It won't be used however since we're going to have apiservers authenticate
	// using client certs
	if cfg.EtcdctlRootUserPassword == "" {
		return fmt.Errorf("[auth] etcd root user password not found in EtcdAdmConfig.EtcdctlRootUserPassword")
	}
	cmdArgs := []string{
		"user",
		"add",
		fmt.Sprintf("root:%s", cfg.EtcdctlRootUserPassword),
	}
	cmd := exec.Command(etcdctl, cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// TODO: eventually handle existing users via something like: strings.Contains(string(out), expected)
		return fmt.Errorf("[auth] `%v` command failed with error: %v", cmd.Args, err)
	}
	fmt.Printf("[auth] %s", out)
	return nil
}

// createUser uses `etcdctl` to create users according to official etcd documentation.
// Equivalent of `etcdctl user add <user>:<random_password>`.
// https://github.com/etcd-io/etcd/blob/master/Documentation/op-guide/authentication.md
func createUser(cfg *apis.EtcdAdmConfig, user string) error {
	etcdctl, err := ensureEtcdctlPath(cfg)
	if err != nil {
		return err
	}
	// Generate a password for non-root users. It won't be used however since we're going to have apiservers authenticate
	// using client certs
	cmdArgs := []string{
		"user",
		"add",
		fmt.Sprintf("%s:%s", user, randomPassword()),
	}
	cmd := exec.Command(etcdctl, cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// TODO: eventually handle existing users via something like: strings.Contains(string(out), expected)
		return fmt.Errorf("[auth] `%v` command failed with error: %v", cmd.Args, err)
	}
	fmt.Printf("[auth] %s", out)
	return nil
}

// ensureEtcdCtlPath is a helper function which ensures we can execute `etcdctl` at the path specified
// by `EtcdAdmnConfig`. We use the wrapper `etcdctl.sh` because it ensures the correct environment values are set
func ensureEtcdctlPath(cfg *apis.EtcdAdmConfig) (string, error) {
	exists, err := util.Exists(cfg.EtcdctlShellWrapper)
	if err != nil {
		return "", fmt.Errorf("[auth] error checking if executable exists at path %s", cfg.EtcdctlShellWrapper)
	}
	if !exists {
		return "", fmt.Errorf("[auth] executable does not exist at path %s", cfg.EtcdctlShellWrapper)
	}

	// TODO: Figure out how to handle 2.x maybe? Not worth IMO
	if strings.HasPrefix(cfg.Version, "2") {
		return "", fmt.Errorf("[auth] enabling auth and creating root user only supported by etcdadm in version 3.x of etcd")
	}
	return cfg.EtcdctlShellWrapper, nil
}

// randomPassword generates a random alphanumeric string without special characters that is 16 characters in length.
// Adapted from https://yourbasic.org/golang/generate-random-string/
func randomPassword() string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	length := 16
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}
