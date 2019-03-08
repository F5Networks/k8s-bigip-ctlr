/*-
 * Copyright (c) 2016-2018, F5 Networks, Inc.
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

package appmanager

import (
	"strconv"

	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"k8s.io/client-go/pkg/api/v1"
)

func (appMgr *Manager) checkAs3ConfigMap(
	obj interface{},
) bool {
	// check for metadata.labels has 'as3' and that 'as3' is set to 'true'
	cm := obj.(*v1.ConfigMap)
	labels := cm.ObjectMeta.Labels
	log.Infof("[as3_log] Parsing labels: %s ", labels)
	if val, ok := labels["as3"]; ok {
		log.Infof("[as3_log] Found AS3 config map...")
		if as3Val, err := strconv.ParseBool(val); err == nil {

			if as3Val {
				//FIXME: Add further processing.
				log.Infof("[as3_log] AS3 Manager to further process...")
				return false
			} else {
				// if AS3 is set to FALSE, return TRUE to enable generic processing
				return true
			}
		} else {
			log.Infof("[as3_log] AS3 value unacceptable. please give true or false. ")
			return true
		}

	} else {
		log.Infof("[as3_log] No AS3 Configuration found.")
		// if as3 variable is not found, just return true for NON-AS3 Processing.
		return true
	}
}
