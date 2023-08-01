package controller

import (
	"context"
	"fmt"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/clustermanager"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"os"
	"strings"
	"sync"

	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	v1 "k8s.io/api/core/v1"
)

// fetch cluster name for given secret if it holds kubeconfig of the cluster.
func (ctlr *Controller) getClusterForSecret(secret *v1.Secret) MultiClusterConfig {
	for _, mcc := range ctlr.resources.multiClusterConfigs {
		// Skip empty/nil configs processing
		if mcc == (MultiClusterConfig{}) {
			continue
		}
		// Check if the secret holds the kubeconfig for a cluster by checking if it's referred in the multicluster config
		// if so then return the cluster name associated with the secret
		if mcc.Secret == (secret.Namespace + "/" + secret.Name) {
			return mcc
		}
	}
	return MultiClusterConfig{}
}

// readMultiClusterConfigFromGlobalCM reads the configuration for multiple kubernetes clusters
func (ctlr *Controller) readMultiClusterConfigFromGlobalCM(haClusterConfig HAClusterConfig, multiClusterConfigs []MultiClusterConfig) error {
	primaryClusterName := ""
	secondaryClusterName := ""
	hACluster := true
	if ctlr.cisType != "" && haClusterConfig != (HAClusterConfig{}) {
		// If HA mode not set use StandBy mode as defualt
		if ctlr.haModeType == "" {
			ctlr.haModeType = StandBy
		}
		// Get the primary and secondary cluster names and store the ratio if operating in ratio mode
		if haClusterConfig.PrimaryCluster != (ClusterDetails{}) {
			primaryClusterName = haClusterConfig.PrimaryCluster.ClusterName
			if ctlr.haModeType == Ratio {
				if haClusterConfig.PrimaryCluster.Ratio != nil {
					ctlr.clusterRatio[haClusterConfig.PrimaryCluster.ClusterName] = haClusterConfig.PrimaryCluster.Ratio
				} else {
					one := 1
					ctlr.clusterRatio[haClusterConfig.PrimaryCluster.ClusterName] = &one
				}
			}
		}
		if haClusterConfig.SecondaryCluster != (ClusterDetails{}) {
			secondaryClusterName = haClusterConfig.SecondaryCluster.ClusterName
			if ctlr.haModeType == Ratio {
				if haClusterConfig.SecondaryCluster.Ratio != nil {
					ctlr.clusterRatio[haClusterConfig.SecondaryCluster.ClusterName] = haClusterConfig.SecondaryCluster.Ratio
				} else {
					one := 1
					ctlr.clusterRatio[haClusterConfig.SecondaryCluster.ClusterName] = &one
				}
			}
		}

		// Set up health probe
		if ctlr.cisType == SecondaryCIS {
			if haClusterConfig.PrimaryClusterEndPoint == "" {
				// cis in secondary mode, primary cluster health check endpoint is required
				// if endpoint is missing exit
				log.Debugf("error: cis running in secondary mode and missing primary cluster health check endPoint. ")
				os.Exit(1)
			} else {
				// process only the updated healthProbe config params
				ctlr.updateHealthProbeConfig(haClusterConfig)
			}
		}

		// Set up the informers for the HA clusters
		if ctlr.cisType == PrimaryCIS {
			if haClusterConfig.SecondaryCluster != (ClusterDetails{}) {
				// Both cluster name and secret are mandatory
				if haClusterConfig.SecondaryCluster.ClusterName == "" || haClusterConfig.SecondaryCluster.Secret == "" {
					log.Errorf("Secondary clusterName or secret not provided in haClusterConfig: %v",
						haClusterConfig.SecondaryCluster)
					os.Exit(1)
				}
				kubeConfigSecret, err := ctlr.fetchKubeConfigSecret(haClusterConfig.SecondaryCluster.Secret,
					haClusterConfig.SecondaryCluster.ClusterName)
				if err != nil {
					log.Errorf(err.Error())
					os.Exit(1)
				}
				err = ctlr.updateClusterConfigStore(kubeConfigSecret,
					MultiClusterConfig{
						ClusterName: haClusterConfig.SecondaryCluster.ClusterName,
						Secret:      haClusterConfig.SecondaryCluster.Secret},
					false)
				if err != nil {
					log.Errorf(err.Error())
					os.Exit(1)
				}

				// Setup and start informers for secondary cluster in case of active-active mode HA cluster
				if ctlr.haModeType == Active || ctlr.haModeType == Ratio {
					err := ctlr.setupAndStartHAClusterInformers(haClusterConfig.SecondaryCluster.ClusterName)
					if err != nil {
						return err
					}
				}
				ctlr.multiClusterConfigs.HAPairCusterName = haClusterConfig.SecondaryCluster.ClusterName
				ctlr.multiClusterConfigs.LocalClusterName = primaryClusterName
			} else {
				hACluster = false
			}
		}
		if ctlr.cisType == SecondaryCIS {
			if haClusterConfig.PrimaryCluster != (ClusterDetails{}) {
				// Both cluster name and secret are mandatory
				if haClusterConfig.PrimaryCluster.ClusterName == "" || haClusterConfig.PrimaryCluster.Secret == "" {
					log.Errorf("Primary clusterName or secret not provided in haClusterConfig: %v",
						haClusterConfig.PrimaryCluster)
					os.Exit(1)
				}
				kubeConfigSecret, err := ctlr.fetchKubeConfigSecret(haClusterConfig.PrimaryCluster.Secret,
					haClusterConfig.PrimaryCluster.ClusterName)
				if err != nil {
					log.Errorf(err.Error())
					os.Exit(1)
				}
				err = ctlr.updateClusterConfigStore(kubeConfigSecret,
					MultiClusterConfig{
						ClusterName: haClusterConfig.PrimaryCluster.ClusterName,
						Secret:      haClusterConfig.PrimaryCluster.Secret},
					false)
				if err != nil {
					log.Errorf(err.Error())
					os.Exit(1)
				}

				// Setup and start informers for primary cluster in case of active-active mode HA cluster
				if ctlr.haModeType == Active || ctlr.haModeType == Ratio {
					err := ctlr.setupAndStartHAClusterInformers(haClusterConfig.PrimaryCluster.ClusterName)
					if err != nil {
						return err
					}
				}
				ctlr.multiClusterConfigs.HAPairCusterName = haClusterConfig.PrimaryCluster.ClusterName
				ctlr.multiClusterConfigs.LocalClusterName = secondaryClusterName
			} else {
				hACluster = false
			}
		}
	} else {
		hACluster = false
	}

	if ctlr.cisType != "" && !hACluster {
		log.Errorf("Either High availability cluster config not provided or --cis-type is provided in Standalone Mode")
		os.Exit(1)
	}

	// Check if multiClusterConfigs are specified for external clusters
	// If multiClusterConfigs is not specified, then clean up any old external cluster related config in case user had
	// specified multiClusterConfig earlier and now removed those configs
	if multiClusterConfigs == nil || len(multiClusterConfigs) == 0 {
		log.Infof("No multi cluster config provided.")
		// Check if any processed data exists from the multiCluster config provided earlier, then remove them
		if ctlr.multiClusterConfigs != nil && len(ctlr.multiClusterConfigs.ClusterConfigs) > 0 {
			for clusterName, _ := range ctlr.multiClusterConfigs.ClusterConfigs {
				// Avoid deleting HA cluster related configs
				if clusterName == primaryClusterName || clusterName == secondaryClusterName {
					continue
				}
				delete(ctlr.multiClusterConfigs.ClusterConfigs, clusterName)
				// Delete cluster ratio as well
				if _, ok := ctlr.clusterRatio[clusterName]; ok {
					delete(ctlr.clusterRatio, clusterName)
				}
			}
		}
		if ctlr.resources.multiClusterConfigs != nil && len(ctlr.resources.multiClusterConfigs) > 0 {
			for clusterName, _ := range ctlr.resources.multiClusterConfigs {
				// Avoid deleting HA cluster related configs
				if clusterName == primaryClusterName || clusterName == secondaryClusterName {
					continue
				}
				delete(ctlr.resources.multiClusterConfigs, clusterName)
			}
		}
		return nil
	}

	currentClusterSecretKeys := make(map[string]struct{})
	for _, mcc := range multiClusterConfigs {

		// Store the cluster keys which will be used to detect deletion of a cluster later
		currentClusterSecretKeys[mcc.ClusterName] = struct{}{}

		// Both cluster name and secret are mandatory
		if mcc.ClusterName == "" || mcc.Secret == "" {
			log.Warningf("clusterName or secret not provided in multiClusterConfig")
			continue
		}

		// Check and discard multiCluster config if an HA cluster is used as external cluster
		if mcc.ClusterName == primaryClusterName || mcc.ClusterName == secondaryClusterName {
			log.Warningf("Discarding usage of cluster %s as external cluster, as HA cluster can't be used as external cluster in multiClusterConfigs.", mcc.ClusterName)
			continue
		}

		// Fetch the secret containing kubeconfig creds
		kubeConfigSecret, err := ctlr.fetchKubeConfigSecret(mcc.Secret, mcc.ClusterName)

		if err != nil {
			log.Warning(err.Error())
			continue
		}

		// Update the new valid cluster config to the multiClusterConfigs cache if not already present
		if _, ok := ctlr.resources.multiClusterConfigs[mcc.ClusterName]; !ok {
			ctlr.resources.multiClusterConfigs[mcc.ClusterName] = mcc
		}

		// If cluster config has been processed already and kubeclient has been created then skip it
		if _, ok := ctlr.multiClusterConfigs.ClusterConfigs[mcc.ClusterName]; ok {
			// Skip processing the cluster config as it's already processed
			// TODO: handle scenarios when cluster names are swapped in the extended config, may be the key should be a
			// combination of cluster name and secret name
			continue
		}

		// Update the clusterKubeConfig
		err = ctlr.updateClusterConfigStore(kubeConfigSecret, mcc, false)
		if err != nil {
			log.Warningf(err.Error())
			continue
		}
		// Set cluster ratio
		if ctlr.haModeType == Ratio {
			if mcc.Ratio != nil {
				ctlr.clusterRatio[mcc.ClusterName] = mcc.Ratio
			} else {
				one := 1
				ctlr.clusterRatio[mcc.ClusterName] = &one
			}
		}
	}
	// Check if a cluster config has been removed then remove the data associated with it from the multiClusterConfigs store
	for clusterName, _ := range ctlr.resources.multiClusterConfigs {
		if _, ok := currentClusterSecretKeys[clusterName]; !ok {
			// Ensure HA cluster config is not deleted
			if clusterName == primaryClusterName || clusterName == secondaryClusterName {
				continue
			}
			// Delete config from the cached valid mutiClusterConfig data
			delete(ctlr.resources.multiClusterConfigs, clusterName)
			// Delegate the deletion of cluster from the clusterConfig store to updateClusterConfigStore so that any
			// additional operations (if any) can be performed
			_ = ctlr.updateClusterConfigStore(nil, MultiClusterConfig{ClusterName: clusterName}, true)
		}
	}
	return nil
}

// updateClusterConfigStore updates the clusterKubeConfigs store with the latest config and updated kubeclient for the cluster
func (ctlr *Controller) updateClusterConfigStore(kubeConfigSecret *v1.Secret, mcc MultiClusterConfig, deleted bool) error {
	if !deleted && (kubeConfigSecret == nil || mcc == (MultiClusterConfig{})) {
		return fmt.Errorf("no secret or MulticlusterConfig specified")
	}
	// if secret associated with a cluster kubeconfig is deleted then remove it from clusterKubeConfig store
	if deleted {
		// Delete kubeclients from multicluster config store
		delete(ctlr.multiClusterConfigs.ClusterConfigs, mcc.ClusterName)
		return nil
	}
	// Extract the kubeconfig from the secret
	kubeConfig, ok := kubeConfigSecret.Data["kubeconfig"]
	if !ok {
		return fmt.Errorf("no kubeconfig data found in the secret: %s for the cluster: %s", mcc.Secret,
			mcc.ClusterName)
	}
	// Create kube client using the provided kubeconfig for the respective cluster
	kubeClient, err := clustermanager.CreateKubeClientFromKubeConfig(&kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubeClient from kube-config fetched from secret %s for the "+
			"cluster %s, Error: %v", mcc.Secret, mcc.ClusterName, err)
	}
	// Update the clusterKubeConfig store
	ctlr.multiClusterConfigs.ClusterConfigs[mcc.ClusterName] = clustermanager.ClusterConfig{
		KubeClient: kubeClient,
	}
	return nil
}

// updateMultiClusterResourceServiceMap updates the multiCluster rscSvcMap and clusterSvcMap
func (ctlr *Controller) updateMultiClusterResourceServiceMap(rsCfg *ResourceConfig, rsRef resourceRef, serviceName, path string,
	pool Pool, servicePort intstr.IntOrString, clusterName string) {
	if _, ok := ctlr.multiClusterResources.rscSvcMap[rsRef]; !ok {
		ctlr.multiClusterResources.rscSvcMap[rsRef] = make(map[MultiClusterServiceKey]MultiClusterServiceConfig)
	}
	svcKey := MultiClusterServiceKey{
		clusterName: clusterName,
		serviceName: serviceName,
		namespace:   pool.ServiceNamespace,
	}
	ctlr.multiClusterResources.rscSvcMap[rsRef][svcKey] = MultiClusterServiceConfig{svcPort: servicePort}
	// update the clusterSvcMap
	ctlr.updatePoolIdentifierForService(svcKey, rsRef, pool.ServicePort, pool.Name, pool.Partition, rsCfg.Virtual.Name, path)
}

// fetchKubeConfigSecret fetches the kubeConfig secret associated with a cluster
func (ctlr *Controller) fetchKubeConfigSecret(secret string, clusterName string) (*v1.Secret, error) {

	// Check if secret is in the desired format of <namespace>/<secret name>
	splits := strings.Split(secret, "/")
	if len(splits) != 2 {
		return nil, fmt.Errorf("secret: %s should be in the format namespace/secret-name", secret)
	}
	secretNamespace := splits[0]
	secretName := splits[1]

	comInf, ok := ctlr.getNamespacedCommonInformer(secretNamespace)
	if !ok {
		log.Warningf("informer not found for namespace: %v", secretNamespace)
	}
	var obj interface{}
	var exist bool
	var err error
	var kubeConfigSecret *v1.Secret
	if comInf != nil && comInf.secretsInformer != nil {
		obj, exist, err = comInf.secretsInformer.GetIndexer().GetByKey(secretName)
		if err != nil {
			log.Warningf("error occurred while fetching Secret: %s for the cluster: %s, Error: %s",
				secretName, clusterName, err)
		}
	}
	if !exist {
		log.Debugf("Fetching secret:%s for cluster:%s using kubeclient", secretName, clusterName)
		// During start up the informers may not be updated so, try to fetch secret using kubeClient
		kubeConfigSecret, err = ctlr.kubeClient.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName,
			metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error occurred while fetching Secret: %s for the cluster: %s, Error: %s",
				secretName, clusterName, err)
		}
	}
	// Fetch the kubeconfig data from the secret
	if kubeConfigSecret == nil {
		kubeConfigSecret = obj.(*v1.Secret)
	}
	return kubeConfigSecret, nil
}

// updateHealthProbeConfig checks for any healthProbe config update and updates the respective healthProbe parameters
func (ctlr *Controller) updateHealthProbeConfig(haClusterConfig HAClusterConfig) {
	// Initialize PrimaryClusterHealthProbeParams if it's the first time
	if ctlr.Agent.PrimaryClusterHealthProbeParams == (PrimaryClusterHealthProbeParams{}) {
		ctlr.Agent.PrimaryClusterHealthProbeParams = PrimaryClusterHealthProbeParams{
			paramLock: &sync.RWMutex{},
		}
	}
	ctlr.Agent.PrimaryClusterHealthProbeParams.paramLock.Lock()
	defer ctlr.Agent.PrimaryClusterHealthProbeParams.paramLock.Unlock()
	// Check if primary cluster health probe endpoint has been updated and set the endpoint type
	if ctlr.Agent.PrimaryClusterHealthProbeParams.EndPoint != haClusterConfig.PrimaryClusterEndPoint {
		ctlr.Agent.PrimaryClusterHealthProbeParams.EndPoint = haClusterConfig.PrimaryClusterEndPoint
		ctlr.Agent.setPrimaryClusterHealthCheckEndPointType()
	}
	// Check if probe interval has been updated
	if haClusterConfig.ProbeInterval == 0 {
		if ctlr.Agent.PrimaryClusterHealthProbeParams.probeInterval != DefaultProbeInterval {
			ctlr.Agent.PrimaryClusterHealthProbeParams.probeInterval = DefaultProbeInterval
		}
	} else if ctlr.Agent.PrimaryClusterHealthProbeParams.probeInterval != haClusterConfig.ProbeInterval {
		ctlr.Agent.PrimaryClusterHealthProbeParams.probeInterval = haClusterConfig.ProbeInterval
	}
	// Check if retry interval has been updated
	if haClusterConfig.RetryInterval == 0 {
		if ctlr.Agent.PrimaryClusterHealthProbeParams.retryInterval != DefaultRetryInterval {
			ctlr.Agent.PrimaryClusterHealthProbeParams.retryInterval = DefaultRetryInterval
		}
	} else if ctlr.Agent.PrimaryClusterHealthProbeParams.retryInterval != haClusterConfig.RetryInterval {
		ctlr.Agent.PrimaryClusterHealthProbeParams.retryInterval = haClusterConfig.RetryInterval
	}
}
