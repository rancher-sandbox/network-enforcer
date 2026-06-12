/*
Copyright 2026.

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

package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "secuity.rancher.io/network-enforcer/api/v1alpha1"
	"secuity.rancher.io/network-enforcer/internal/backend"
)

const enforceLabelKey = "security.rancher.io/enforce"

type EnforcementReconciler struct {
	client.Client

	Scheme  *runtime.Scheme
	Backend backend.PolicyBackend
}

// +kubebuilder:rbac:groups=security.security.rancher.io,resources=networkpolicyproposals,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.security.rancher.io,resources=networkpolicyproposals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch

func (r *EnforcementReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var proposal securityv1alpha1.NetworkPolicyProposal
	if err := r.Get(ctx, req.NamespacedName, &proposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	enforced := proposal.Labels[enforceLabelKey] == "true"
	// if the policy is not enforced, nothing to do here
	if !enforced {
		return ctrl.Result{}, nil
	}
	// todo!: we need to convert the proposal to a real policy
	log.Info("[still to implement] enforce policy", "name", proposal.Name, "namespace", proposal.Namespace)

	return ctrl.Result{}, nil
}

func (r *EnforcementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.NetworkPolicyProposal{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				oldLabels := e.ObjectOld.GetLabels()
				newLabels := e.ObjectNew.GetLabels()
				return oldLabels[enforceLabelKey] != newLabels[enforceLabelKey]
			},
			CreateFunc:  func(e event.CreateEvent) bool { return true },
			DeleteFunc:  func(e event.DeleteEvent) bool { return false },
			GenericFunc: func(e event.GenericEvent) bool { return false },
		}).
		Named("enforcement").
		Complete(r)
}
