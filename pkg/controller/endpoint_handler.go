package controller

import (
	"encoding/json"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	corev1 "k8s.io/api/core/v1"
	"time"
)

func (eq *EndpointQueue) Push(obj *rqKey) {
	eq.Lock()
	defer eq.Unlock()

	eq.queue = append(eq.queue, obj)
}

func (eq *EndpointQueue) PopAll() []*rqKey {
	eq.Lock()
	defer eq.Unlock()
	queue := eq.queue
	eq.queue = []*rqKey{}
	return queue
}

func (ctlr *Controller) getUpdatedServiceList() SvcMap {
	svcMap := make(SvcMap)
	for _, rKey := range ctlr.endpointQueue.PopAll() {
		rscDelete := false
		if rKey.event == Delete {
			rscDelete = true
		}
		switch rKey.kind {
		case Pod:
			pod := rKey.rsc.(*corev1.Pod)
			_ = ctlr.processPod(pod, rscDelete)
			svc := ctlr.GetServicesForPod(pod, rKey.clusterName)
			if nil == svc {
				break
			}
			svcKey := MultiClusterServiceKey{
				serviceName: svc.Name,
				namespace:   svc.Namespace,
				clusterName: rKey.clusterName,
			}
			// Don't process the service as it's not used by any resource
			if _, ok := ctlr.resources.poolMemCache[svcKey]; !ok {
				log.Debugf("Skipping pod '%v/%v' as it's not used by any CIS monitored resource", pod.Namespace, pod.Name)
				break
			}
			if _, ok := svcMap[svcKey]; !ok {
				svcMap[svcKey] = svc
			}
		case Endpoints:
			ep := rKey.rsc.(*corev1.Endpoints)
			svc := ctlr.getServiceForEndpoints(ep)
			// No Services are effected with the change in service.
			if nil == svc {
				break
			}
			svcKey := MultiClusterServiceKey{
				serviceName: svc.Name,
				namespace:   svc.Namespace,
				clusterName: rKey.clusterName,
			}
			// Don't process the service as it's not used by any resource
			if _, ok := ctlr.resources.poolMemCache[svcKey]; !ok {
				log.Debugf("Skipping endpoint '%v/%v' as it's not used by any CIS monitored resource", ep.Namespace, ep.Name)
				break
			}
			if _, ok := svcMap[svcKey]; !ok {
				svcMap[svcKey] = svc
			}
		}
	}
	return svcMap
}

func (ctlr *Controller) EndpointHandler() {
	for {
		svcMap := ctlr.getUpdatedServiceList()
		if len(svcMap) > 0 {
			key := &rqKey{
				kind: ServiceList,
				rsc:  svcMap,
			}
			ctlr.resourceQueue.Add(key)
		}
		time.Sleep(1 * time.Second) // Sleep for 1 second
	}
}

// processPod populates NPL annotations for a pod in store.
func (ctlr *Controller) processPod(pod *corev1.Pod, ispodDeleted bool) error {
	ctlr.resources.nplStore.Lock()
	defer ctlr.resources.nplStore.Unlock()
	podKey := pod.Namespace + "/" + pod.Name
	if ispodDeleted {
		delete(ctlr.resources.nplStore.NPLMap, podKey)
		return nil
	}
	ann := pod.GetAnnotations()
	var annotations []NPLAnnotation
	if val, ok := ann[NPLPodAnnotation]; ok {
		if err := json.Unmarshal([]byte(val), &annotations); err != nil {
			log.Errorf("key: %s, got error while unmarshaling NPL annotations: %v", podKey, err)
		}
		ctlr.resources.nplStore.NPLMap[podKey] = annotations
	} else {
		log.Debugf("key: %s, NPL annotation not found for Pod", pod.Name)
		delete(ctlr.resources.nplStore.NPLMap, podKey)
	}
	return nil
}
