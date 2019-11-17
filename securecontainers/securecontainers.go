//
// Copyright (c) 2019 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

package securecontainers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	b64 "encoding/base64"
	"github.com/kata-containers/agent/crypto"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	agentName                = "kata-agent"
	configmapFileName        = "kavach.properties"
	configmapJsonFileName    = "config.json"
	kataGuestSvmDir          = "/run/svm"
	kataGuestSharedDir       = "/run/kata-containers/shared/containers"
	skopeoSrcImageTransport  = "docker://" //Todo: Handle other registries as well
	skopeoDestImageTransport = "oci:"
	configmapMountPoint      = "/etc/kavach"
)

var agentFields = logrus.Fields{
	"name":   agentName,
	"pid":    os.Getpid(),
	"source": "agent",
}

var agentLog = logrus.WithFields(agentFields)
var svmConfig SVMConfig
var ociJsonSpec = &specs.Spec{}

type SVMConfig struct {
	Spec Spec `yaml:"spec"`
}
type Requests struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
}
type Resources struct {
	Requests Requests `yaml:"requests"`
}
type Env struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}
type Ports struct {
	ContainerPort int `yaml:"containerPort"`
}
type Containers struct {
	Name      string    `yaml:"name"`
	Image     string    `yaml:"image"`
	Resources Resources `yaml:"resources"`
	Args      []string  `yaml:"args"`
	Env       []Env     `yaml:"env"`
	Cwd       string    `yaml:"cwd"`
	Ports     []Ports   `yaml:"ports"`
}
type Spec struct {
	Containers []Containers `yaml:"containers"`
}

func CheckIfPauseContainer(args []string) bool {

	pause_args := "/pause"

	for _, n := range args {
		if len(args) == 1 && pause_args == n {
			agentLog.Debug("It is a pause image")
			return true
		}
	}

	return false
}

func StartSecureContainers(ociSpec *specs.Spec, req *pb.CreateContainerRequest) error {

	err := readEncryptedConfigmap(req, ociSpec.Process.Env)
	if err != nil {
		agentLog.WithError(err).Errorf("readEncryptedConfigmap errored out: %s", err)
		return err
	}

	err = pullOciImage(ociSpec, svmConfig, req)
	if err != nil {
		agentLog.WithError(err).Errorf("pullSecureImage errored out: %s", err)
		return err
	}

	err = createRuntimeBundle(ociSpec, req)
	if err != nil {
		agentLog.WithError(err).Errorf("createRuntimeBundle errored out: %s", err)
		return err
	}

	updateOCIReq(ociSpec, req, svmConfig)

	ociBundle := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_bundle")
	ociSpec.Root.Path = filepath.Join(ociBundle, "rootfs")

	return nil
}

//Read encrypted configmap volume mounted into the scratch image.
func readEncryptedConfigmap(req *pb.CreateContainerRequest, vaultEnv []string) error {

	var file string
	for _, mounts := range req.OCI.Mounts {
		if mounts.Destination == configmapMountPoint {
			file = filepath.Join(mounts.Source, configmapFileName)
			agentLog.Debug("Found encrypted configmap at:", mounts.Source)
			break
		}
	}

	if len(file) == 0 {
		return fmt.Errorf("No encrypted configmap found")
	}

	_, err := os.Stat(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Unable to stat file %s err:%s", file, err)
		return err
	}
	agentLog.WithField("ConfigMap path: ", file).Debug("Found file for reading config map")
	yamlContainerSpec, err := ioutil.ReadFile(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not read file %s: %s", file, err)
		return err
	}

	containerspec, err := b64.StdEncoding.DecodeString(string(yamlContainerSpec)) //decoded into an encoded blob
	if err != nil {
		return err
	}

	key, nonce, err := crypto.GetCMDecryptionKey(vaultEnv)
	if err != nil {
		return err
	}

	decryptedConfig, err := crypto.DecryptSVMConfig(containerspec, key, nonce)
	if err != nil {
		return err
	}

	persistDecryptedCM(req.ContainerId, decryptedConfig)

	err = yaml.Unmarshal(decryptedConfig, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml %s", err)
		return err
	}

	return err

}

func createRuntimeBundle(ociSpec *specs.Spec, req *pb.CreateContainerRequest) error {

	ociBundle := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_bundle")
	ociImage := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_dir")

	agentLog.WithField("ociImage is: ", ociImage).Debug("Creating runtime bundle")
	agentLog.WithField("ociBundle is: ", ociBundle).Debug("Creating runtime bundle")

	// Since image.CreateRuntimeBundleLayout is returning a nil pointer exception, os exec the oci-image-tool directly
	cmd := exec.Command("oci-image-tool", "create", "--ref=platform.os=linux", ociImage, ociBundle)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		agentLog.WithField("ocibundle err: ", err).Debug("create oci bundle failed")
	}

	_, err = os.Stat(ociBundle)
	if err != nil {
		agentLog.WithError(err).Errorf("ociBundle does not exists: %s", ociBundle)
		return err
	} else {
		agentLog.WithField("ociBundle: ", ociBundle).Debug("Created ociBundle successfully")
	}

	// Make ociBundle executable as some images need to execute .sh files at startup
	cmd = exec.Command("chmod", "-R", "+x", ociBundle)
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		agentLog.WithError(err).Errorf("chmod failed %s", err)
		return err
	}

	return err
}

func persistDecryptedCM(containerId string, decryptedConfig []byte) error {

	decryptCMFile := filepath.Join(kataGuestSvmDir, containerId, "decryptedConfig")
	decryptCMDir := filepath.Join(kataGuestSvmDir, containerId)

	agentLog.Debug("Create directory to write decrypted configmap into: ", decryptCMDir)
	err := os.MkdirAll(decryptCMDir, os.ModeDir)
	if err != nil {
		return err
	}

	agentLog.Debug("Write decrypted configmap into: ", decryptCMFile)
	err = ioutil.WriteFile(decryptCMFile, decryptedConfig, 0644)
	return err
}

func pullOciImage(ociSpec *specs.Spec, svmConfig SVMConfig, req *pb.CreateContainerRequest) error {

	var out bytes.Buffer
	var stderr bytes.Buffer

	pull := skopeoSrcImageTransport + svmConfig.Spec.Containers[0].Image
	create_dir := filepath.Join(kataGuestSvmDir, req.ContainerId, "rootfs_dir:latest")
	destRefString := skopeoDestImageTransport + create_dir

	err := os.MkdirAll(create_dir, os.ModeDir)
	if err != nil {
		agentLog.WithError(err).Errorf("Error creating directory %s %s", create_dir, err)
		return err
	}

	cmd := exec.Command("skopeo", "copy", pull, destRefString)
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		agentLog.WithError(err).Errorf("Error executing skopeo copy %s", err)
		return err
	}

	return nil
}

func UpdateExecProcessConfig(containerId string, processEnv []string, processCwd string) ([]string, string, error) {
	decryptedConfig := filepath.Join(kataGuestSvmDir, containerId, "decryptedConfig")
	data, err := ioutil.ReadFile(decryptedConfig)
	err = yaml.Unmarshal(data, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml while execing inside container %s", err)
		return processEnv, processCwd, err
	}

	ociJsonSpec, err = ReadOciImageConfigJson(containerId)
	if err != nil {
		agentLog.WithError(err).Errorf("readConfigJson errored out: %s", err)
		return processEnv, processCwd, err
	}

	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		processEnv = UpdateEnv(processEnv, ociJsonSpec.Process.Env, svmConfig)
	}

	processCwd = UpdateCwd(processCwd, ociJsonSpec.Process.Cwd, svmConfig)
	ociJsonSpec = &specs.Spec{}
	svmConfig = SVMConfig{}
	return processEnv, processCwd, nil
}

func ReadOciImageConfigJson(containerId string) (*specs.Spec, error) {

	configPath := filepath.Join(kataGuestSvmDir, containerId, "rootfs_bundle", "config.json")
	agentLog.Debug("Reading configJSONBytes from %s", configPath)

	_, err := os.Stat(configPath)
	if err != nil {
		agentLog.WithError(err).Errorf("ConfigPath does not exsists %s", configPath)
		return ociJsonSpec, err
	}

	configJSONBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not open OCI config file %s", configPath)
		return ociJsonSpec, err
	}

	agentLog.Debug("Unmarshalling the data")
	if err := json.Unmarshal(configJSONBytes, &ociJsonSpec); err != nil {
		agentLog.WithError(err).Errorf("Could not unmarshall OCI config file")
		return ociJsonSpec, err
	}

	return ociJsonSpec, nil
}

func UpdateEnv(ociEnv []string, ociJsonEnv []string, svmConfig SVMConfig) []string {
	ociEnv = append(ociEnv, ociJsonEnv...)
	for i := 0; i < len(svmConfig.Spec.Containers[0].Env); i++ {
		createEnv := svmConfig.Spec.Containers[0].Env[i].Name + "=" + svmConfig.Spec.Containers[0].Env[i].Value
		ociEnv = append(ociEnv, createEnv)
	}
	return ociEnv
}

func UpdateCwd(ociCwd string, ociJsonCwd string, svmConfig SVMConfig) string {
	if svmConfig.Spec.Containers[0].Cwd != "" {
		ociCwd = svmConfig.Spec.Containers[0].Cwd
	} else {
		ociCwd = ociJsonCwd
	}
	return ociCwd
}

func updateOCIReq(ociSpec *specs.Spec, req *pb.CreateContainerRequest, svmConfig SVMConfig) {

	ociJsonSpec, err := ReadOciImageConfigJson(req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("readOciImageConfigJson Errored out: %s", err)
	}

	// Give higher priority to args specified in the pod yaml in CM than json spec of the image
	if len(svmConfig.Spec.Containers[0].Args) == 0 {
		req.OCI.Process.Args = ociJsonSpec.Process.Args
	} else {
		req.OCI.Process.Args = svmConfig.Spec.Containers[0].Args
	}

	//      req.OCI.Process.Env = append(req.OCI.Process.Env, ociJsonSpec.Process.Env...)
	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		req.OCI.Process.Env = UpdateEnv(req.OCI.Process.Env, ociJsonSpec.Process.Env, svmConfig)
	}

	req.OCI.Process.Cwd = UpdateCwd(req.OCI.Process.Cwd, ociJsonSpec.Process.Cwd, svmConfig)

}
