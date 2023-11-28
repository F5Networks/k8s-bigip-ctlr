/*-
 * Copyright (c) 2019-2021, F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package controller

import (
	"context"
	bigIPPrometheus "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/prometheus"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

func (ctlr *Controller) enableHttpEndpoint(httpAddress string) {
	// Expose Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	bigIPPrometheus.RegisterMetrics(ctlr.Agent.PostManager.HTTPClientMetrics)
	// Expose cis health endpoint
	http.Handle("/health", ctlr.CISHealthCheckHandler())
	log.Fatal(http.ListenAndServe(httpAddress, nil).Error())
}

func (ctlr *Controller) CISHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ctlr.clientsets.kubeClient != nil {
			var response string
			// Check if kube-api server is reachable
			_, err := ctlr.clientsets.kubeClient.Discovery().RESTClient().Get().AbsPath(clusterHealthPath).DoRaw(context.TODO())
			if err != nil {
				response = "kube-api server is not reachable."
			}
			// TODO Check if Central Manager is reachable
			// Check if big-ip server is reachable
			//_, _, _, err2 := ctlr.Agent.GetBigipAS3Version()
			//if err2 != nil {
			//	response = response + "big-ip server is not reachable."
			//}
			// if err2 == nil && err == nil {
			if err == nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Ok"))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(response))
			}
		}
	})
}
