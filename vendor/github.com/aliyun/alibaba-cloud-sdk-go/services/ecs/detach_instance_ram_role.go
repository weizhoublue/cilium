package ecs

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// DetachInstanceRamRole invokes the ecs.DetachInstanceRamRole API synchronously
func (client *Client) DetachInstanceRamRole(request *DetachInstanceRamRoleRequest) (response *DetachInstanceRamRoleResponse, err error) {
	response = CreateDetachInstanceRamRoleResponse()
	err = client.DoAction(request, response)
	return
}

// DetachInstanceRamRoleWithChan invokes the ecs.DetachInstanceRamRole API asynchronously
func (client *Client) DetachInstanceRamRoleWithChan(request *DetachInstanceRamRoleRequest) (<-chan *DetachInstanceRamRoleResponse, <-chan error) {
	responseChan := make(chan *DetachInstanceRamRoleResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.DetachInstanceRamRole(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// DetachInstanceRamRoleWithCallback invokes the ecs.DetachInstanceRamRole API asynchronously
func (client *Client) DetachInstanceRamRoleWithCallback(request *DetachInstanceRamRoleRequest, callback func(response *DetachInstanceRamRoleResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *DetachInstanceRamRoleResponse
		var err error
		defer close(result)
		response, err = client.DetachInstanceRamRole(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// DetachInstanceRamRoleRequest is the request struct for api DetachInstanceRamRole
type DetachInstanceRamRoleRequest struct {
	*requests.RpcRequest
	ResourceOwnerId      requests.Integer `position:"Query" name:"ResourceOwnerId"`
	ResourceOwnerAccount string           `position:"Query" name:"ResourceOwnerAccount"`
	RamRoleName          string           `position:"Query" name:"RamRoleName"`
	OwnerId              requests.Integer `position:"Query" name:"OwnerId"`
	InstanceIds          string           `position:"Query" name:"InstanceIds"`
}

// DetachInstanceRamRoleResponse is the response struct for api DetachInstanceRamRole
type DetachInstanceRamRoleResponse struct {
	*responses.BaseResponse
	RequestId                    string                       `json:"RequestId" xml:"RequestId"`
	TotalCount                   int                          `json:"TotalCount" xml:"TotalCount"`
	FailCount                    int                          `json:"FailCount" xml:"FailCount"`
	RamRoleName                  string                       `json:"RamRoleName" xml:"RamRoleName"`
	DetachInstanceRamRoleResults DetachInstanceRamRoleResults `json:"DetachInstanceRamRoleResults" xml:"DetachInstanceRamRoleResults"`
}

// CreateDetachInstanceRamRoleRequest creates a request to invoke DetachInstanceRamRole API
func CreateDetachInstanceRamRoleRequest() (request *DetachInstanceRamRoleRequest) {
	request = &DetachInstanceRamRoleRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Ecs", "2014-05-26", "DetachInstanceRamRole", "ecs", "openAPI")
	request.Method = requests.POST
	return
}

// CreateDetachInstanceRamRoleResponse creates a response to parse from DetachInstanceRamRole response
func CreateDetachInstanceRamRoleResponse() (response *DetachInstanceRamRoleResponse) {
	response = &DetachInstanceRamRoleResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
