// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	lyftaws "github.com/lyft/cni-ipvlan-vpc-k8s/aws"
	"github.com/sirupsen/logrus"
)

const (
	defaultPreAllocation = 8
)

var (
	awsSession        *session.Session
	ec2Client         ec2iface.EC2API
	metadataClient    *ec2metadata.EC2Metadata
	identityDocument  *ec2metadata.EC2InstanceIdentityDocument
	allocationTrigger *trigger.Trigger
)

type instance struct {
	enis map[string]*v2.ENI
}

type instanceMap map[string]*instance

func (m instanceMap) add(eni *v2.ENI) {
	i, ok := m[eni.InstanceID]
	if !ok {
		i = &instance{}
		m[eni.InstanceID] = i
	}

	if i.enis == nil {
		i.enis = map[string]*v2.ENI{}
	}

	i.enis[eni.ID] = eni
}

type tags map[string]string

func (t tags) match(required tags) bool {
	for k, neededvalue := range required {
		haveValue, ok := t[k]
		if !ok || (ok && neededvalue != haveValue) {
			return false
		}
	}
	return true
}

type subnet struct {
	ID                 string
	Name               string
	CIDR               string
	AvailabilityZone   string
	VpcID              string
	AvailableAddresses int
	Tags               tags
}

type subnetMap map[string]*subnet

type instancesManager struct {
	mutex     lock.RWMutex
	instances instanceMap
	subnets   subnetMap
}

func (m *instancesManager) getSubnet(subnetID string) *subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.subnets[subnetID]
}

func (m *instancesManager) findSubnetByTags(vpcID, availabilityZone string, required tags) (bestSubnet *subnet) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VpcID == vpcID && s.AvailabilityZone == availabilityZone && s.Tags.match(required) {
			if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
				bestSubnet = s
			}
		}
	}

	return
}

func (m *instancesManager) updateENI(eni *v2.ENI) {
	m.mutex.Lock()
	m.instances.add(eni)
	m.mutex.Unlock()
}

func (m *instancesManager) resync() {
	instances, vpcs, err := getInstanceInterfaces()
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 interface list")
		return
	}

	subnets, err := getSubnets(vpcs)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve EC2 subnets list")
		return
	}

	log.Infof("Synchronized %d ENIs and %d subnets", len(instances), len(subnets))

	m.mutex.Lock()
	m.instances = instances
	m.subnets = subnets
	m.mutex.Unlock()
}

func (m *instancesManager) getENIs(instanceID string) []*v2.ENI {
	enis := []*v2.ENI{}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if i, ok := m.instances[instanceID]; ok {
		for _, e := range i.enis {
			enis = append(enis, e.DeepCopy())
		}
	}

	return enis
}

var instances = instancesManager{instances: instanceMap{}}

type ciliumNode struct {
	name            string
	neededAddresses int
	resource        *v2.CiliumNode
}

type ciliumNodeMap map[string]*ciliumNode

type nodeManager struct {
	mutex lock.RWMutex
	nodes ciliumNodeMap
}

var ciliumNodes = nodeManager{nodes: ciliumNodeMap{}}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func indexExists(enis []*v2.ENI, index int) bool {
	for _, e := range enis {
		if e.Number == index {
			return true
		}
	}
	return false
}

func (n *ciliumNode) allocateENI(s *subnet, enis []*v2.ENI) {
	scopedLog := log.WithFields(logrus.Fields{
		"instanceID":     n.resource.Spec.ENI.InstanceID,
		"securityGroups": n.resource.Spec.ENI.SecurityGroups,
		"subnetID":       s.ID,
	})

	log.Infof("Allocating ENI")

	createReq := &ec2.CreateNetworkInterfaceInput{}
	createReq.SetDescription("Cilium-CNI (" + n.resource.Spec.ENI.InstanceID + ")")
	secGrpsPtr := []*string{}
	for _, grp := range n.resource.Spec.ENI.SecurityGroups {
		newgrp := grp // Need to copy
		secGrpsPtr = append(secGrpsPtr, &newgrp)
	}

	createReq.SetGroups(secGrpsPtr)
	createReq.SetSubnetId(s.ID)

	resp, err := ec2Client.CreateNetworkInterface(createReq)
	if err != nil {
		scopedLog.WithError(err).Warning("Unable to create ENI")
		return
	}

	eniID := *resp.NetworkInterface.NetworkInterfaceId
	scopedLog = scopedLog.WithField("eniID", eniID)
	scopedLog.Info("Created new ENI")

	var index int
	for indexExists(enis, index) {
		index++
	}

	attachReq := &ec2.AttachNetworkInterfaceInput{}
	attachReq.SetDeviceIndex(int64(index))
	attachReq.SetInstanceId(n.resource.Spec.ENI.InstanceID)
	attachReq.SetNetworkInterfaceId(eniID)

	attachResp, err := ec2Client.AttachNetworkInterface(attachReq)
	if err != nil {
		delReq := &ec2.DeleteNetworkInterfaceInput{}
		delReq.SetNetworkInterfaceId(*resp.NetworkInterface.NetworkInterfaceId)

		_, delErr := ec2Client.DeleteNetworkInterface(delReq)
		if delErr != nil {
			scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
		}

		scopedLog.WithError(err).Warningf("Unable to attach ENI at index %d", index)
		return
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"attachmentID": *attachResp.AttachmentId,
		"index":        index,
	})
	scopedLog.Info("Attached ENI to instance")

	// We have an attachment ID from the last API, which lets us mark the
	// interface as delete on termination
	changes := &ec2.NetworkInterfaceAttachmentChanges{}
	changes.SetAttachmentId(*attachResp.AttachmentId)
	changes.SetDeleteOnTermination(true)
	modifyReq := &ec2.ModifyNetworkInterfaceAttributeInput{}
	modifyReq.SetAttachment(changes)
	modifyReq.SetNetworkInterfaceId(*resp.NetworkInterface.NetworkInterfaceId)

	_, err = ec2Client.ModifyNetworkInterfaceAttribute(modifyReq)
	if err != nil {
		log.WithError(err).Warning("Unable to mark ENI for deletion on termination")
	}
}

func (n *ciliumNode) canAllocate(enis []*v2.ENI, limits lyftaws.ENILimit, neededAddresses int) (*v2.ENI, *subnet, int) {
	for _, e := range enis {
		if e.Number >= n.resource.Spec.ENI.FirstAllocationInterface && len(e.Addresses) < limits.IPv4 {
			if subnet := instances.getSubnet(e.Subnet.ID); subnet != nil {
				if subnet.AvailableAddresses > 0 {
					return e, subnet, min(subnet.AvailableAddresses, neededAddresses)
				}
			}
		}
	}

	return nil, nil, 0
}

func (n *ciliumNode) allocate() {
	scopedLog := log.WithField("node", n.name)

	limits := lyftaws.ENILimitsForInstanceType("m5.large")
	enis := instances.getENIs(n.resource.Spec.ENI.InstanceID)
	if len(enis) == 0 {
		return
	}

	if e, subnet, available := n.canAllocate(enis, limits, n.neededAddresses); subnet != nil {
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"eniID":        e.ID,
			"subnetID":     subnet.ID,
			"availableIPs": available,
		})

		scopedLog.Infof("Allocating IP on existing ENI")

		request := ec2.AssignPrivateIpAddressesInput{NetworkInterfaceId: &e.ID}
		request.SetSecondaryPrivateIpAddressCount(int64(available))

		if _, err := ec2Client.AssignPrivateIpAddresses(&request); err != nil {
			scopedLog.WithError(err).Warning("Unable to assign %d additional private IPs to ENI %s", available, e.ID)
		}

		// IPs were allocated, they will be picked up with the next refresh
		go func() {
			instances.resync()
		}()

		return
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"vpcID":            enis[0].VPC.ID,
		"availabilityZone": enis[0].AvailabilityZone,
		"subnetTags":       n.resource.Spec.ENI.SubnetTags,
	})
	scopedLog.Infof("No more IPs available, creating new ENI")

	if len(enis) >= limits.Adapters {
		log.Warningf("Instance %s is out of ENIs", n.resource.Spec.ENI.InstanceID)
		return
	}

	bestSubnet := instances.findSubnetByTags(enis[0].VPC.ID, enis[0].AvailabilityZone, n.resource.Spec.ENI.SubnetTags)
	if bestSubnet == nil {
		scopedLog.Warning("No subnets available to allocate ENI")
		return
	}

	n.allocateENI(bestSubnet, enis)

	// ENI was allocated, resync
	go func() {
		instances.resync()
	}()
}

func (n *ciliumNode) refresh() {
	if n.neededAddresses > 0 {
		if allocationTrigger != nil {
			allocationTrigger.TriggerWithReason(n.name)
		}
	}

	node := n.resource.DeepCopy()

	if node.Spec.IPAM.Available == nil {
		node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	}

	if node.Status.IPAM.InUse == nil {
		node.Status.IPAM.InUse = map[string]v2.AllocationIP{}
	}

	relevantENIs := instances.getENIs(n.resource.Spec.ENI.InstanceID)
	node.Status.ENI.ENIs = map[string]v2.ENI{}
	node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	for _, e := range relevantENIs {
		node.Status.ENI.ENIs[e.ID] = *e

		if e.Number < node.Spec.ENI.FirstAllocationInterface {
			continue
		}

		for _, ip := range e.Addresses {
			node.Spec.IPAM.Available[ip] = v2.AllocationIP{Resource: e.ID}
		}
	}

	var statusErr, specErr error
	var newNode *v2.CiliumNode

	// If k8s supports status as a sub-resource, then we need to update the status separately
	k8sCapabilities := k8sversion.Capabilities()
	switch {
	case k8sCapabilities.UpdateStatus:
		if !reflect.DeepEqual(n.resource.Spec, node.Spec) {
			newNode, specErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
			if newNode != nil {
				n.resource = newNode
			}
		}
		if !reflect.DeepEqual(n.resource.Status, node.Status) {
			_, statusErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").UpdateStatus(node)
			if newNode != nil {
				n.resource = newNode
			}
		}
	default:
		if !reflect.DeepEqual(n.resource, node) {
			_, specErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
			if newNode != nil {
				n.resource = newNode
			}
		}
	}

	if specErr != nil {
		log.WithError(specErr).Warningf("Unable to update spec of CiliumNode %s", node.Name)
	}

	if statusErr != nil {
		log.WithError(statusErr).Warningf("Unable to update status of CiliumNode %s", node.Name)
	}
}

func (n *nodeManager) Update(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	node, ok := n.nodes[resource.Name]
	if !ok {
		node = &ciliumNode{
			name: resource.Name,
		}
		n.nodes[node.name] = node
	}
	node.resource = resource

	requiredAddresses := resource.Spec.ENI.PreAllocate
	if requiredAddresses == 0 {
		requiredAddresses = defaultPreAllocation
	}

	availableIPs := len(resource.Spec.IPAM.Available)
	usedIPs := len(resource.Status.IPAM.InUse)
	node.neededAddresses = requiredAddresses - (availableIPs - usedIPs)
	if node.neededAddresses > 0 {
		if allocationTrigger != nil {
			allocationTrigger.TriggerWithReason(node.name)
		}
	}

	log.WithFields(logrus.Fields{
		"instanceID":      resource.Spec.ENI.InstanceID,
		"addressesNeeded": node.neededAddresses,
	}).Infof("Updated node %s", resource.Name)
}

func (n *nodeManager) Delete(nodeName string) {
	n.mutex.Lock()
	delete(n.nodes, nodeName)
	n.mutex.Unlock()
}

func (n *nodeManager) allocateForNode(nodeName string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	node, ok := n.nodes[nodeName]
	if ok {
		node.allocate()
	}
}

func (n *nodeManager) refresh() {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for _, node := range n.nodes {
		node.refresh()
	}
}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, aws.String(value))
	}
	return filter
}

func convertToENI(iface *ec2.NetworkInterface) (v2.ENI, error) {
	if iface.PrivateIpAddress == nil {
		return v2.ENI{}, fmt.Errorf("ENI has no IP address")
	}

	eni := v2.ENI{
		IP:             *iface.PrivateIpAddress,
		SecurityGroups: []string{},
		Addresses:      []string{},
	}

	if iface.AvailabilityZone != nil {
		eni.AvailabilityZone = *iface.AvailabilityZone
	}

	if iface.MacAddress != nil {
		eni.MAC = *iface.MacAddress
	}

	if iface.NetworkInterfaceId != nil {
		eni.ID = *iface.NetworkInterfaceId
	}

	if iface.Description != nil {
		eni.Description = *iface.Description
	}

	if iface.Attachment != nil {
		if iface.Attachment.DeviceIndex != nil {
			eni.Number = int(*iface.Attachment.DeviceIndex)
		}

		if iface.Attachment.InstanceId != nil {
			eni.InstanceID = *iface.Attachment.InstanceId
		}
	}

	if iface.SubnetId != nil {
		eni.Subnet.ID = *iface.SubnetId
	}

	if iface.VpcId != nil {
		eni.VPC.ID = *iface.VpcId
	}

	for _, ip := range iface.PrivateIpAddresses {
		if ip.PrivateIpAddress != nil {
			eni.Addresses = append(eni.Addresses, *ip.PrivateIpAddress)
		}
	}

	//	for _, ip := range iface.Ipv6Addresses {
	//		if ip.Ipv6Address {
	//			eni.Addresses = append(eni.Addresses, *ip.Ipv6Address)
	//		}
	//	}

	for _, g := range iface.Groups {
		if g.GroupId != nil {
			eni.SecurityGroups = append(eni.SecurityGroups, *g.GroupId)
		}
	}

	return eni, nil
}

func getInstanceInterfaces() (instanceMap, map[string]string, error) {
	instances := instanceMap{}
	vpcs := map[string]string{}

	req := ec2.DescribeNetworkInterfacesInput{}
	response, err := ec2Client.DescribeNetworkInterfaces(&req)
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range response.NetworkInterfaces {
		eni, err := convertToENI(iface)
		if err != nil {
			log.WithError(err).Warning("Unable to convert NetworkInterface to internal representation")
		} else {
			instances.add(&eni)
			vpcs[eni.VPC.ID] = eni.AvailabilityZone
		}
	}

	return instances, vpcs, nil
}

func getSubnets(vpcs map[string]string) (subnetMap, error) {
	subnets := subnetMap{}

	input := &ec2.DescribeSubnetsInput{}
	result, err := ec2Client.DescribeSubnets(input)
	if err != nil {
		return nil, err
	}

	for _, s := range result.Subnets {
		subnet := &subnet{
			ID:                 *s.SubnetId,
			CIDR:               *s.CidrBlock,
			AvailableAddresses: int(*s.AvailableIpAddressCount),
			Tags:               map[string]string{},
		}

		if s.AvailabilityZone != nil {
			subnet.AvailabilityZone = *s.AvailabilityZone
		}

		if s.VpcId != nil {
			subnet.VpcID = *s.VpcId
		}

		for _, tag := range s.Tags {
			if *tag.Key == "Name" {
				subnet.Name = *tag.Value
			} else {
				subnet.Tags[*tag.Key] = *tag.Value
			}
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

func allocateTrigger(reasons []string) {
	for _, nodeName := range reasons {
		ciliumNodes.allocateForNode(nodeName)
	}
}

func startENIAllocator() error {
	log.Info("Starting ENI allocator...")

	awsSession = session.Must(session.NewSession())
	metadataClient = ec2metadata.New(awsSession)

	instance, err := metadataClient.GetInstanceIdentityDocument()
	if err != nil {
		return fmt.Errorf("unable to retrieve instance identity document: %s", err)
	}

	allocationTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-allocation",
		MinInterval: 5 * time.Second,
		TriggerFunc: allocateTrigger,
	})
	if err != nil {
		return fmt.Errorf("unable to initialize trigger: %s", err)
	}

	identityDocument = &instance
	ec2Client = ec2.New(awsSession, aws.NewConfig().WithRegion(identityDocument.Region))

	log.Infof("Connected to metadata server")

	instances.resync()
	ciliumNodes.refresh()

	log.Info("Starting ENI operator...")
	mngr := controller.NewManager()
	mngr.UpdateController("eni-refresh",
		controller.ControllerParams{
			RunInterval: time.Minute,
			DoFunc: func(_ context.Context) error {
				log.Debugf("Refreshing CiliumNode resources...")
				instances.resync()
				ciliumNodes.refresh()
				return nil
			},
		})

	return nil
}
