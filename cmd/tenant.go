/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	log "sigs.k8s.io/etcdadm/pkg/logrus"

	"github.com/spf13/cobra"

	"sigs.k8s.io/etcdadm/apis"
	"sigs.k8s.io/etcdadm/auth"
)


var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Creates a user and assigns it full read/write access to a specified prefix that will be created if it doesn't exist",
	Run: func(cmd *cobra.Command, args []string) {
		apis.SetDefaults(&etcdAdmConfig)
		if err := apis.SetInitDynamicDefaults(&etcdAdmConfig); err != nil {
			log.Fatalf("[defaults] Error: %s", err)
		}

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			log.Fatalf("Error parsing option value for name")
		}

		if err = auth.CreateTenant(&etcdAdmConfig, name); err != nil {
			log.Fatalf("[tenant] Error: %s", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(tenantCmd)
	// TODO: Make --name flag required
	tenantCmd.Flags().String("name", "", "Specify name to be used as: client cert Common Name(CN), user, role, and prefix. The user is given readwrite access to the prefix of the same name. The prefix is created at the root of etcd for now.")
	tenantCmd.MarkFlagRequired("name")
	// tenantCmd.Flags().String("prefix", "", "The etcd prefix path to grant full read/write access to user")
}
