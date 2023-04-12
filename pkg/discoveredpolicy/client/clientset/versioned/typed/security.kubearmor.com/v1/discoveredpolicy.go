/*
Copyright 2023.

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
// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"
	"time"

	v1 "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/api/security.kubearmor.com/v1"
	scheme "github.com/accuknox/auto-policy-discovery/pkg/discoveredpolicy/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// DiscoveredPoliciesGetter has a method to return a DiscoveredPolicyInterface.
// A group's client should implement this interface.
type DiscoveredPoliciesGetter interface {
	DiscoveredPolicies(namespace string) DiscoveredPolicyInterface
}

// DiscoveredPolicyInterface has methods to work with DiscoveredPolicy resources.
type DiscoveredPolicyInterface interface {
	Create(ctx context.Context, discoveredPolicy *v1.DiscoveredPolicy, opts metav1.CreateOptions) (*v1.DiscoveredPolicy, error)
	Update(ctx context.Context, discoveredPolicy *v1.DiscoveredPolicy, opts metav1.UpdateOptions) (*v1.DiscoveredPolicy, error)
	UpdateStatus(ctx context.Context, discoveredPolicy *v1.DiscoveredPolicy, opts metav1.UpdateOptions) (*v1.DiscoveredPolicy, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.DiscoveredPolicy, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.DiscoveredPolicyList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.DiscoveredPolicy, err error)
	DiscoveredPolicyExpansion
}

// discoveredPolicies implements DiscoveredPolicyInterface
type discoveredPolicies struct {
	client rest.Interface
	ns     string
}

// newDiscoveredPolicies returns a DiscoveredPolicies
func newDiscoveredPolicies(c *SecurityV1Client, namespace string) *discoveredPolicies {
	return &discoveredPolicies{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the discoveredPolicy, and returns the corresponding discoveredPolicy object, and an error if there is any.
func (c *discoveredPolicies) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.DiscoveredPolicy, err error) {
	result = &v1.DiscoveredPolicy{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of DiscoveredPolicies that match those selectors.
func (c *discoveredPolicies) List(ctx context.Context, opts metav1.ListOptions) (result *v1.DiscoveredPolicyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.DiscoveredPolicyList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested discoveredPolicies.
func (c *discoveredPolicies) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a discoveredPolicy and creates it.  Returns the server's representation of the discoveredPolicy, and an error, if there is any.
func (c *discoveredPolicies) Create(ctx context.Context, discoveredPolicy *v1.DiscoveredPolicy, opts metav1.CreateOptions) (result *v1.DiscoveredPolicy, err error) {
	result = &v1.DiscoveredPolicy{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(discoveredPolicy).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a discoveredPolicy and updates it. Returns the server's representation of the discoveredPolicy, and an error, if there is any.
func (c *discoveredPolicies) Update(ctx context.Context, discoveredPolicy *v1.DiscoveredPolicy, opts metav1.UpdateOptions) (result *v1.DiscoveredPolicy, err error) {
	result = &v1.DiscoveredPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		Name(discoveredPolicy.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(discoveredPolicy).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *discoveredPolicies) UpdateStatus(ctx context.Context, discoveredPolicy *v1.DiscoveredPolicy, opts metav1.UpdateOptions) (result *v1.DiscoveredPolicy, err error) {
	result = &v1.DiscoveredPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		Name(discoveredPolicy.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(discoveredPolicy).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the discoveredPolicy and deletes it. Returns an error if one occurs.
func (c *discoveredPolicies) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *discoveredPolicies) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("discoveredpolicies").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched discoveredPolicy.
func (c *discoveredPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.DiscoveredPolicy, err error) {
	result = &v1.DiscoveredPolicy{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("discoveredpolicies").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
